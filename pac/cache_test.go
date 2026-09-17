package pac

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"
)

type countingFinder struct {
	mu      sync.Mutex
	proxies Proxies
	err     error
	calls   int
}

func (f *countingFinder) FindProxyForURL(in *url.URL) (Proxies, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.proxies, f.err
}

func (f *countingFinder) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestCachingProxyFinderKeyedByHostAndPath(t *testing.T) {
	inner := &countingFinder{proxies: Proxies{{Hostname: "p.example", Port: 8080}}}
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewCachingProxyFinder(inner, WithProxyCacheClock(func() time.Time { return clock }))

	// Same host+path, different scheme/port/query-equal => one inner call.
	for _, raw := range []string{"http://a.example/x", "https://a.example:8443/x"} {
		if _, err := c.FindProxyForURL(mustParse(t, raw)); err != nil {
			t.Fatal(err)
		}
	}
	if got := inner.count(); got != 1 {
		t.Fatalf("expected 1 inner call for identical host+path, got %d", got)
	}
	// Different path on the same host is a separate entry: path-based PAC
	// scripts (shExpMatch on the URL) must not get a wrong cached answer.
	if _, err := c.FindProxyForURL(mustParse(t, "http://a.example/y")); err != nil {
		t.Fatal(err)
	}
	if got := inner.count(); got != 2 {
		t.Fatalf("expected distinct paths to be distinct entries, got %d", got)
	}
	// Different host likewise.
	if _, err := c.FindProxyForURL(mustParse(t, "http://b.example/x")); err != nil {
		t.Fatal(err)
	}
	if got := inner.count(); got != 3 {
		t.Fatalf("expected 3 inner calls, got %d", got)
	}
	// Query strings participate in the key too.
	if _, err := c.FindProxyForURL(mustParse(t, "http://b.example/x?a=1")); err != nil {
		t.Fatal(err)
	}
	if got := inner.count(); got != 4 {
		t.Fatalf("expected query to participate in the key, got %d", got)
	}
	if _, err := c.FindProxyForURL(mustParse(t, "http://b.example/x?a=1")); err != nil {
		t.Fatal(err)
	}
	if got := inner.count(); got != 4 {
		t.Fatalf("expected identical URL cache hit, got %d", got)
	}
}

func TestCachingProxyFinderTTLEntryExpiry(t *testing.T) {
	inner := &countingFinder{proxies: Proxies{DirectProxy}}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewCachingProxyFinder(inner,
		WithProxyCacheTTL(time.Minute),
		WithProxyCacheClock(func() time.Time { return now }),
	)
	if _, err := c.FindProxyForURL(mustParse(t, "http://a.example/")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Second)
	if _, err := c.FindProxyForURL(mustParse(t, "http://a.example/")); err != nil {
		t.Fatal(err)
	}
	if inner.count() != 1 {
		t.Fatalf("expected fresh entry served from cache, calls=%d", inner.count())
	}
	now = now.Add(time.Minute)
	if _, err := c.FindProxyForURL(mustParse(t, "http://a.example/")); err != nil {
		t.Fatal(err)
	}
	if inner.count() != 2 {
		t.Fatalf("expected expired entry re-resolved, calls=%d", inner.count())
	}
}

func TestCachingProxyFinderZeroTTLDisables(t *testing.T) {
	inner := &countingFinder{proxies: Proxies{DirectProxy}}
	c := NewCachingProxyFinder(inner, WithProxyCacheTTL(0))
	for i := 0; i < 3; i++ {
		if _, err := c.FindProxyForURL(mustParse(t, "http://a.example/")); err != nil {
			t.Fatal(err)
		}
	}
	if inner.count() != 3 {
		t.Fatalf("expected TTL<=0 to bypass the cache, calls=%d", inner.count())
	}
}

func TestCachingProxyFinderBoundsSize(t *testing.T) {
	inner := &countingFinder{proxies: Proxies{DirectProxy}}
	c := NewCachingProxyFinder(inner, WithProxyCacheSize(4))
	for i := 0; i < 50; i++ {
		if _, err := c.FindProxyForURL(mustParse(t, "http://host"+strconv.Itoa(i)+".example/")); err != nil {
			t.Fatal(err)
		}
	}
	entries, _, _ := c.Stats()
	if entries != 4 {
		t.Fatalf("expected cache bounded to 4 entries, got %d", entries)
	}
}

func TestCachingProxyFinderInvalidate(t *testing.T) {
	inner := &countingFinder{proxies: Proxies{DirectProxy}}
	c := NewCachingProxyFinder(inner)
	c.FindProxyForURL(mustParse(t, "http://a.example/"))
	c.FindProxyForURL(mustParse(t, "http://b.example/"))
	c.Invalidate("a.example/")
	entries, _, _ := c.Stats()
	if entries != 1 {
		t.Fatalf("expected 1 remaining entry, got %d", entries)
	}
	c.Invalidate("")
	entries, _, _ = c.Stats()
	if entries != 0 {
		t.Fatalf("expected full flush, got %d", entries)
	}
}

func TestCachingProxyFinderErrorCachingAndStats(t *testing.T) {
	boom := errors.New("pac error")
	inner := &countingFinder{err: boom}
	c := NewCachingProxyFinder(inner)
	if _, err := c.FindProxyForURL(mustParse(t, "http://a.example/")); err != boom {
		t.Fatalf("expected wrapped error, got %v", err)
	}
	if _, err := c.FindProxyForURL(mustParse(t, "http://a.example/")); err != boom {
		t.Fatalf("expected cached error, got %v", err)
	}
	if inner.count() != 1 {
		t.Fatalf("expected errors to be cached too, calls=%d", inner.count())
	}
	entries, lookups, hits := c.Stats()
	if entries != 1 || lookups != 2 || hits != 1 {
		t.Fatalf("unexpected stats: entries=%d lookups=%d hits=%d", entries, lookups, hits)
	}
}

func TestCachingProxyFinderEmptyHostBypasses(t *testing.T) {
	inner := &countingFinder{proxies: Proxies{DirectProxy}}
	c := NewCachingProxyFinder(inner)
	// opaque/origin-form request: no hostname available, never cache
	nonURL := &url.URL{}
	if _, err := c.FindProxyForURL(nonURL); err != nil {
		t.Fatal(err)
	}
	if _, err := c.FindProxyForURL(nonURL); err != nil {
		t.Fatal(err)
	}
	if inner.count() != 2 {
		t.Fatalf("expected hostless URLs bypass the cache, calls=%d", inner.count())
	}
	entries, _, _ := c.Stats()
	if entries != 0 {
		t.Fatalf("expected nothing cached, entries=%d", entries)
	}
}

func TestCachingProxyFinderConcurrency(t *testing.T) {
	inner := &countingFinder{proxies: Proxies{{Hostname: "p", Port: 1}}}
	c := NewCachingProxyFinder(inner, WithProxyCacheSize(16))
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := c.FindProxyForURL(mustParse(t, fmt.Sprintf("http://h%d.example/", i%20))); err != nil {
				t.Errorf("find: %v", err)
			}
		}(i)
	}
	wg.Wait()
	entries, _, _ := c.Stats()
	if entries > 16 {
		t.Fatalf("cache exceeded bound: %d", entries)
	}
}
