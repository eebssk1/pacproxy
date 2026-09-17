package pacfunc

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// withScratchCaches swaps the package-level caches and resolver for the
// duration of body, so tests never interfere with each other's state.
func withScratchCaches(t *testing.T, resolve func(host string) (*net.IPAddr, error), size int, body func()) {
	t.Helper()
	origResolve, origNower, origDNS, origShExp := resolveIPAddr, DefaultNower, dnsLookupCache, shExpCache
	resolveIPAddr = resolve
	dnsLookupCache = newDNSCache(size)
	shExpCache = newLRURegexp(size)
	defer func() {
		resolveIPAddr, DefaultNower, dnsLookupCache, shExpCache =
			origResolve, origNower, origDNS, origShExp
	}()
	body()
}

func TestShExpRegexpReusesCompiledExpressions(t *testing.T) {
	withScratchCaches(t, nil, 8, func() {
		const shexp = "*.example.com"
		re1, err := shExpRegexp(shexp)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		re2, err := shExpRegexp(shexp)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if re1 != re2 {
			t.Fatal("expected the cached *regexp.Regexp pointer to be reused")
		}
	})
}

func TestShExpRegexpEvictsLeastRecentlyUsed(t *testing.T) {
	withScratchCaches(t, nil, 2, func() {
		for i := 0; i < 2; i++ {
			if _, err := shExpRegexp("pat" + strconv.Itoa(i)); err != nil {
				t.Fatal(err)
			}
		}
		// Touch pat0 so pat1 becomes the least recently used entry.
		if _, err := shExpRegexp("pat0"); err != nil {
			t.Fatal(err)
		}
		if _, err := shExpRegexp("pat2"); err != nil {
			t.Fatal(err)
		}
		if _, ok := shExpCache.get("pat1"); ok {
			t.Fatal("expected pat1 to have been evicted")
		}
		if _, ok := shExpCache.get("pat0"); !ok {
			t.Fatal("expected pat0 to still be cached")
		}
		if shExpCache.order.Len() != 2 {
			t.Fatalf("expected cache bounded at 2, got %d", shExpCache.order.Len())
		}
	})
}

func TestShExpMatchSemanticsUnchanged(t *testing.T) {
	cases := []struct {
		str, shexp string
		want       bool
	}{
		{"http://home.netscape.com/people/ari/index.html", "*/ari/*", true},
		{"http://home.netscape.com/people/montulli/index.html", "*/ari/*", false},
		{"www.example.com", "*.example.com", true},
		{"wwwXexample.com", "www.example.com", false},
		{"a", "?", true},
		{"ab", "?", false},
		{"anything", "*", true},
	}
	for _, c := range cases {
		if got := ShExpMatch(c.str, c.shexp); got != c.want {
			t.Errorf("ShExpMatch(%q,%q)=%v want %v", c.str, c.shexp, got, c.want)
		}
	}
}

func TestResolveHostCachedSingleLookupPerTTL(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fixed := &TimeNower{static: &now}
	calls := 0

	withScratchCaches(t, func(host string) (*net.IPAddr, error) {
		calls++
		return &net.IPAddr{IP: net.IPv4(1, 2, 3, 4)}, nil
	}, DefaultDNSCacheSize, func() {
		DefaultNower = fixed
		for i := 0; i < 5; i++ {
			addr, err := resolveHostCached("example.com")
			if err != nil || addr == nil || addr.String() != "1.2.3.4" {
				t.Fatalf("unexpected resolve result: %v %v", addr, err)
			}
		}
		if calls != 1 {
			t.Fatalf("expected 1 resolver call for 5 hits, got %d", calls)
		}
	})
}

func TestResolveHostCachedTTLExpiry(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := start
	fixed := &TimeNower{}
	fixed.static = &now
	calls := 0

	withScratchCaches(t, func(host string) (*net.IPAddr, error) {
		calls++
		return &net.IPAddr{IP: net.IPv4(1, 2, 3, 4)}, nil
	}, DefaultDNSCacheSize, func() {
		DefaultNower = fixed
		if _, err := resolveHostCached("example.com"); err != nil {
			t.Fatal(err)
		}
		now = start.Add(DNSPositiveTTL - time.Minute)
		if _, err := resolveHostCached("example.com"); err != nil {
			t.Fatal(err)
		}
		if calls != 1 {
			t.Fatalf("expected cache hit before expiry, resolver calls=%d", calls)
		}
		now = start.Add(DNSPositiveTTL + time.Minute)
		if _, err := resolveHostCached("example.com"); err != nil {
			t.Fatal(err)
		}
		if calls != 2 {
			t.Fatalf("expected re-resolve after TTL, resolver calls=%d", calls)
		}
	})
}

func TestResolveHostCachedNegativeTTL(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := start
	fixed := &TimeNower{}
	fixed.static = &now
	calls := 0
	boom := errors.New("no such host")

	withScratchCaches(t, func(host string) (*net.IPAddr, error) {
		calls++
		return nil, boom
	}, DefaultDNSCacheSize, func() {
		DefaultNower = fixed
		if _, err := resolveHostCached("broken.example"); err != boom {
			t.Fatalf("expected error, got %v", err)
		}
		if _, err := resolveHostCached("broken.example"); err != boom {
			t.Fatalf("expected cached error, got %v", err)
		}
		if calls != 1 {
			t.Fatalf("expected failures to be cached, resolver calls=%d", calls)
		}
		now = start.Add(DNSNegativeTTL + time.Second)
		if _, err := resolveHostCached("broken.example"); err != boom {
			t.Fatalf("expected re-resolve after negative TTL, got %v", err)
		}
		if calls != 2 {
			t.Fatalf("expected negative entry to expire, resolver calls=%d", calls)
		}
	})
}

func TestDNSCacheIsBounded(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fixed := &TimeNower{static: &now}
	withScratchCaches(t, func(host string) (*net.IPAddr, error) {
		return &net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}, nil
	}, 8, func() {
		DefaultNower = fixed
		for i := 0; i < 100; i++ {
			if _, err := resolveHostCached("host" + strconv.Itoa(i)); err != nil {
				t.Fatal(err)
			}
		}
		if dnsLookupCache.order.Len() != 8 {
			t.Fatalf("expected cache bounded to 8 entries, got %d", dnsLookupCache.order.Len())
		}
	})
}

func TestResolveHostCachedEmptyHost(t *testing.T) {
	withScratchCaches(t, func(host string) (*net.IPAddr, error) {
		t.Fatal("resolver must not be called for an empty host")
		return nil, nil
	}, 8, func() {
		if _, err := resolveHostCached(""); err == nil {
			t.Fatal("expected an error for an empty host")
		}
		if DNSResolve("") != "" {
			t.Fatal("DNSResolve(\"\") should be empty")
		}
		if IsResolvable("") {
			t.Fatal("IsResolvable(\"\") should be false")
		}
	})
}

func TestDNSCacheConcurrency(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fixed := &TimeNower{static: &now}
	withScratchCaches(t, func(host string) (*net.IPAddr, error) {
		return &net.IPAddr{IP: net.IPv4(9, 9, 9, 9)}, nil
	}, DefaultDNSCacheSize, func() {
		DefaultNower = fixed
		var wg sync.WaitGroup
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if _, err := resolveHostCached("host" + strconv.Itoa(i%12)); err != nil {
					t.Errorf("resolve: %v", err)
				}
			}(i)
		}
		wg.Wait()
	})
}

func TestClearResetsCaches(t *testing.T) {
	withScratchCaches(t, func(host string) (*net.IPAddr, error) {
		return &net.IPAddr{IP: net.IPv4(1, 1, 1, 1)}, nil
	}, 8, func() {
		if _, err := resolveHostCached("a.example"); err != nil {
			t.Fatal(err)
		}
		if _, err := shExpRegexp("*.example"); err != nil {
			t.Fatal(err)
		}
		Clear()
		if dnsLookupCache.order.Len() != 0 || shExpCache.order.Len() != 0 {
			t.Fatal("Clear() must empty both caches")
		}
	})
}
