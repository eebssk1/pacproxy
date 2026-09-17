package pac

import (
	"container/list"
	"net/url"
	"sync"
	"time"
)

// Defaults for CachingProxyFinder. They are intentionally modest: the cache
// exists to keep the (single, mutex-guarded) JavaScript VM off the hot path
// rather than to memorise every host a browser will ever touch.
const (
	// DefaultProxyCacheSize bounds the number of cached hostnames.
	DefaultProxyCacheSize = 2048
	// DefaultProxyCacheTTL is how long a cached decision stays valid.
	DefaultProxyCacheTTL = 5 * time.Minute
)

// proxyCacheEntry stores a resolved decision for one cache key.
type proxyCacheEntry struct {
	key     string
	proxies Proxies
	err     error
	expires time.Time
}

// CachingProxyFinder decorates a ProxyFinder with a bounded, TTL'd LRU cache
// keyed on the request host and path.
//
// Evaluating a PAC file means running interpreted JavaScript while holding an
// exclusive lock, so every repeated lookup is both slow and serialising for
// other requests. Caching the decision removes that work for every URL that
// is seen more than once, which in practice is the overwhelming majority of
// a browser session's traffic.
//
// Residual staleness comes only from scripts that branch on time-of-day
// helpers (weekdayRange/timeRange/dateRange) or on myIpAddress: their answers
// can be up to one TTL old. Set a zero TTL to disable caching for those.
type CachingProxyFinder struct {
	mu      sync.Mutex
	inner   ProxyFinder
	maxSize int
	ttl     time.Duration
	now     func() time.Time

	items map[string]*list.Element
	order *list.List

	// lookups/hits counters are advisory stats, updated under mu.
	lookups uint64
	hits    uint64
}

// CachingOpt configures a CachingProxyFinder.
type CachingOpt func(*CachingProxyFinder)

// WithProxyCacheSize overrides the maximum number of cached entries.
func WithProxyCacheSize(n int) CachingOpt {
	return func(c *CachingProxyFinder) { c.maxSize = n }
}

// WithProxyCacheTTL overrides the entry lifetime. A non-positive TTL disables
// caching entirely, which is the documented escape hatch for time-sensitive or
// path-sensitive PAC scripts.
func WithProxyCacheTTL(d time.Duration) CachingOpt {
	return func(c *CachingProxyFinder) { c.ttl = d }
}

// WithProxyCacheClock injects a clock, used by tests.
func WithProxyCacheClock(now func() time.Time) CachingOpt {
	return func(c *CachingProxyFinder) { c.now = now }
}

// NewCachingProxyFinder wraps inner with a bounded per-host decision cache.
func NewCachingProxyFinder(inner ProxyFinder, opts ...CachingOpt) *CachingProxyFinder {
	c := &CachingProxyFinder{
		inner:   inner,
		maxSize: DefaultProxyCacheSize,
		ttl:     DefaultProxyCacheTTL,
		now:     time.Now,
		items:   make(map[string]*list.Element),
		order:   list.New(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// proxyCacheKey reduces a URL to the identity a PAC decision is keyed on.
//
// The key is the path (plus query, when present) scoped by the hostname. The
// scheme and port deliberately do not participate so http/https and
// alternate-port variants of the same resource share one entry, but the path
// is part of the key because many PAC scripts branch on it via
// shExpMatch(url, "*/private/*") and similar; keying on the host alone would
// serve those scripts a wrong decision.
//
// Remaining known staleness window: scripts that branch on time-of-day or
// weekday helpers can be up to one TTL out of date; disable the cache with a
// zero TTL if your script relies on them.
func proxyCacheKey(in *url.URL) (string, bool) {
	if in == nil {
		return "", false
	}
	host := in.Hostname()
	if host == "" {
		return "", false
	}
	key := host + in.EscapedPath()
	if in.RawQuery != "" {
		key += "?" + in.RawQuery
	}
	return key, true
}

// FindProxyForURL returns the cached proxy list for the request host when a
// fresh entry exists, falling back to the wrapped finder otherwise.
func (c *CachingProxyFinder) FindProxyForURL(in *url.URL) (Proxies, error) {
	key, ok := proxyCacheKey(in)
	if !ok || c.ttl <= 0 {
		return c.inner.FindProxyForURL(in)
	}

	c.mu.Lock()
	c.lookups++
	if el, hit := c.items[key]; hit {
		entry := el.Value.(*proxyCacheEntry)
		if c.now().Before(entry.expires) {
			c.hits++
			c.order.MoveToFront(el)
			proxies := entry.proxies
			c.mu.Unlock()
			return proxies, entry.err
		}
		c.order.Remove(el)
		delete(c.items, key)
	}
	c.mu.Unlock()

	proxies, err := c.inner.FindProxyForURL(in)

	// Failures are cached under the same TTL as successes. A PAC script
	// that throws does so consistently for a given URL, and re-running
	// the interpreted VM on every request while it is broken would both
	// hammer the single-threaded engine and return the same error; the
	// entry expires after the TTL so a fixed script heals naturally.
	if err != nil {
		proxies = Proxies{}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.maxSize > 0 {
		entry := &proxyCacheEntry{
			key:     key,
			proxies: proxies,
			err:     err,
			expires: c.now().Add(c.ttl),
		}
		c.items[key] = c.order.PushFront(entry)
		for c.order.Len() > c.maxSize {
			if el := c.order.Back(); el != nil {
				c.order.Remove(el)
				delete(c.items, el.Value.(*proxyCacheEntry).key)
			}
		}
	}
	return proxies, err
}

// Invalidate drops a single cache entry (see proxyCacheKey for the key
// format), or every entry when key is empty. It is exported so a PAC reload
// can flush stale decisions.
func (c *CachingProxyFinder) Invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if key == "" {
		c.order.Init()
		c.items = make(map[string]*list.Element)
		return
	}
	if el, ok := c.items[key]; ok {
		c.order.Remove(el)
		delete(c.items, key)
	}
}

// Stats reports the cache size plus cumulative lookups and hits.
func (c *CachingProxyFinder) Stats() (entries int, lookups, hits uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len(), c.lookups, c.hits
}
