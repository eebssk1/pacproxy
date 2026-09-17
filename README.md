pacproxy
========

[![Build Status](https://travis-ci.org/williambailey/pacproxy.svg)](https://travis-ci.org/williambailey/pacproxy)

A no-frills local HTTP proxy server powered by a [proxy auto-config (PAC) file](https://web.archive.org/web/20070602031929/http://wp.netscape.com/eng/mozilla/2.0/relnotes/demo/proxy-live.html). Especially handy when you are working in an environment with many different proxy servers and your applications don't support proxy auto-configuration.

```
$ ./pacproxy -h
pacproxy v2.1.0

A no-frills local HTTP proxy server powered by a proxy auto-config (PAC) file
https://github.com/williambailey/pacproxy

Usage:
  -c string
        PAC file name, url or javascript to use (required)
  -l string
        Interface and port to listen on (default "127.0.0.1:8080")
  -r string
        Resolve the proxies for the provided url to STDOUT and exit
  -t duration
        how long a PAC decision is cached, keyed on URL host+path (default "5m0s");
        set 0 to disable caching (for scripts that branch on time)
  -v    send verbose output to STDERR
```

```bash
# shell 1
pacproxy -c 'function FindProxyForURL(url, host){ console.log("hello pac world!"); return "PROXY random.example.com:8080"; }'
# shell 2
export http_proxy="127.0.0.1:8080"
export https_proxy="127.0.0.1:8080"
curl -I "http://www.example.com"
```

```bash
pacproxy -c 'function FindProxyForURL(url, host){ return "PROXY random.example.com:8080"; }' -r "http://www.example.com"
```

## Performance notes

- PAC decisions are cached per URL host+path (`-t`, default 5m) so the
  interpreted JavaScript VM does not serialise every request.
  `SIGHUP` reloads the PAC and flushes the cache atomically.
- Shell-expression (`shExpMatch`) regexes and `dnsResolve`/`isInNet`/
  `isResolvable` host lookups are memoised in small bounded caches
  (LRU + TTL) instead of being recompiled/re-resolved per request.
- TCP keep-alive probes are tuned on tunnels (30s idle, 10s interval,
  3 failures) so quiet long-lived connections survive NAT timeouts and
  dead peers are reclaimed.
- CONNECT tunnels relay with splice-backed zero-copy where available,
  with half-close (FIN forwarding) instead of a hard 10ms teardown, and
  hop-by-hop headers are stripped rather than leaked across hops.
  Measured locally: ~35% more keep-alive requests/s and ~2.5x tunnel
  throughput versus 2.0.7, with lower idle RSS.

## License

> Copyright 2026 William Bailey
>
> Licensed under the Apache License, Version 2.0 (the "License");
> you may not use this file except in compliance with the License.
> You may obtain a copy of the License at
>
>     http://www.apache.org/licenses/LICENSE-2.0
>
> Unless required by applicable law or agreed to in writing, software
> distributed under the License is distributed on an "AS IS" BASIS,
> WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
> See the License for the specific language governing permissions and
> limitations under the License.
