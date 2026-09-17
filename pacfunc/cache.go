package pacfunc

import (
	"container/list"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// This file implements small, bounded caches shared by the PAC helper
// functions. PAC scripts are evaluated for every single proxied request and
// commonly call the same helpers (shExpMatch, dnsResolve, isInNet,
// isResolvable...) over and over with the same arguments. The caches remove
// that repeated work:
//
//   - shell-expression regexps are compiled once and kept in an LRU,
//   - DNS lookups are memoised with a short TTL in a size bounded cache.
//
// Both caches are deliberately capped so that a long running proxy cannot
// accumulate unbounded resident memory.

// ---------------------------------------------------------------------------
// Compiled shell expression (shExpMatch) cache
// ---------------------------------------------------------------------------

// DefaultShExpCacheSize is the maximum number of compiled shell expressions
// kept around. Each entry is a small *regexp.Regexp; a few hundred entries
// cost only a few tens of KiB.
const DefaultShExpCacheSize = 128

// shExpReplacer converts a shell expression into regexp source in a single
// pass, replacing the older chain of three strings.Replace calls (which
// allocated a new string each time).
var shExpReplacer = strings.NewReplacer(`.`, `\.`, `?`, `.?`, `*`, `.*`)

type cachedRegexp struct {
	key string
	re  *regexp.Regexp
}

// lruRegexp is a mutex guarded LRU of compiled regular expressions.
type lruRegexp struct {
	mu      sync.Mutex
	maxSize int
	items   map[string]*list.Element
	order   *list.List
}

func newLRURegexp(maxSize int) *lruRegexp {
	return &lruRegexp{
		maxSize: maxSize,
		items:   make(map[string]*list.Element),
		order:   list.New(),
	}
}

func (c *lruRegexp) get(key string) (*regexp.Regexp, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.MoveToFront(el)
		return el.Value.(*cachedRegexp).re, true
	}
	return nil, false
}

func (c *lruRegexp) put(key string, re *regexp.Regexp) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		el.Value.(*cachedRegexp).re = re
		c.order.MoveToFront(el)
		return
	}
	c.items[key] = c.order.PushFront(&cachedRegexp{key: key, re: re})
	for c.order.Len() > c.maxSize {
		if el := c.order.Back(); el != nil {
			c.order.Remove(el)
			delete(c.items, el.Value.(*cachedRegexp).key)
		}
	}
}

var shExpCache = newLRURegexp(DefaultShExpCacheSize)

// shExpRegexp returns the compiled regexp matching an entire string against
// the given shell expression. Compiled expressions are cached.
func shExpRegexp(shexp string) (*regexp.Regexp, error) {
	if re, ok := shExpCache.get(shexp); ok {
		return re, nil
	}
	re, err := regexp.Compile("^" + shExpReplacer.Replace(shexp) + "$")
	if err != nil {
		return nil, err
	}
	shExpCache.put(shexp, re)
	return re, nil
}

// ---------------------------------------------------------------------------
// DNS resolution cache
// ---------------------------------------------------------------------------

const (
	// DefaultDNSCacheSize bounds the number of cached hostnames.
	DefaultDNSCacheSize = 512
	// DNSPositiveTTL is how long a successful lookup is cached.
	DNSPositiveTTL = 5 * time.Minute
	// DNSNegativeTTL is how long a failed lookup is cached. Kept short so a
	// transient resolver failure does not stick around for long.
	DNSNegativeTTL = 15 * time.Second
)

type dnsEntry struct {
	key     string
	addr    *net.IPAddr
	err     error
	expires time.Time
}

// dnsCache memoises net.ResolveIPAddr lookups with a TTL, bounded in size by
// an LRU eviction policy. The clock comes from DefaultNower so tests can
// control expiry.
type dnsCache struct {
	mu      sync.Mutex
	maxSize int
	items   map[string]*list.Element
	order   *list.List
}

func newDNSCache(maxSize int) *dnsCache {
	return &dnsCache{
		maxSize: maxSize,
		items:   make(map[string]*list.Element),
		order:   list.New(),
	}
}

func (c *dnsCache) get(host string) (dnsEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := DefaultNower.Now()
	if el, ok := c.items[host]; ok {
		entry := el.Value.(*dnsEntry)
		if now.Before(entry.expires) {
			c.order.MoveToFront(el)
			return *entry, true
		}
		c.order.Remove(el)
		delete(c.items, host)
	}
	return dnsEntry{}, false
}

func (c *dnsCache) put(entry dnsEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[entry.key]; ok {
		el.Value.(*dnsEntry).expires = entry.expires
		c.order.MoveToFront(el)
		return
	}
	c.items[entry.key] = c.order.PushFront(&entry)
	for c.order.Len() > c.maxSize {
		if el := c.order.Back(); el != nil {
			c.order.Remove(el)
			delete(c.items, el.Value.(*dnsEntry).key)
		}
	}
}

// Clear resets the caches. It is safe to call at any time and is used when
// the underlying PAC engine is reloaded and by tests.
func Clear() {
	shExpCache.mu.Lock()
	shExpCache.order.Init()
	shExpCache.items = make(map[string]*list.Element)
	shExpCache.mu.Unlock()
	dnsLookupCache.mu.Lock()
	dnsLookupCache.order.Init()
	dnsLookupCache.items = make(map[string]*list.Element)
	dnsLookupCache.mu.Unlock()
}

var dnsLookupCache = newDNSCache(DefaultDNSCacheSize)

// resolveIPAddr is the function used for actual lookups. It is a variable so
// tests can inject a fake resolver without needing the network.
var resolveIPAddr = func(host string) (*net.IPAddr, error) {
	return net.ResolveIPAddr("ip", host)
}

// errEmptyHost is returned (and cached) when an empty hostname is resolved.
var errEmptyHost = &net.AddrError{Err: "empty host", Addr: ""}

// resolveHostCached resolves host, memoising both positive and negative
// results in the bounded TTL cache.
func resolveHostCached(host string) (*net.IPAddr, error) {
	if host == "" {
		return nil, errEmptyHost
	}
	if entry, ok := dnsLookupCache.get(host); ok {
		return entry.addr, entry.err
	}
	addr, err := resolveIPAddr(host)
	entry := dnsEntry{key: host, addr: addr, err: err}
	ttl := DNSPositiveTTL
	if err != nil || addr == nil {
		ttl = DNSNegativeTTL
	}
	entry.expires = DefaultNower.Now().Add(ttl)
	dnsLookupCache.put(entry)
	return addr, err
}
