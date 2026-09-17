package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/williambailey/pacproxy/pac"
)

// Name of the app
const Name = "pacproxy"

// Version of the app
const Version = "2.1.0"

// About the app
const About = "A no-frills local HTTP proxy server powered by a proxy auto-config (PAC) file"

// Repo where the app is located
const Repo = "https://github.com/williambailey/pacproxy"

var (
	fPac        string
	fListen     string
	fVerbose    bool
	fResolveURL string
	fCacheTTL   time.Duration
)

func init() {
	flag.StringVar(&fPac, "c", "", "PAC file name, url or javascript to use (required)")
	flag.StringVar(&fListen, "l", "127.0.0.1:8080", "Interface and port to listen on")
	flag.BoolVar(&fVerbose, "v", false, "send verbose output to STDERR")
	flag.StringVar(&fResolveURL, "r", "", "Resolve the proxies for the provided url to STDOUT and exit")
	flag.DurationVar(
		&fCacheTTL,
		"t",
		pac.DefaultProxyCacheTTL,
		"how long a PAC decision is cached, keyed on URL host+path "+
			"(0 disables caching; set 0 for scripts that branch on time)",
	)
}

func main() {
	flag.Usage = func() {
		// fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "%s v%s\n\n%s\n%s\n\nUsage:\n", Name, Version, About, Repo)
		flag.PrintDefaults()
	}
	flag.Parse()

	seen := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	required := []string{"c"}
	for _, req := range required {
		if !seen[req] {
			exitWithUsage(fmt.Sprintf("Missing required flag -%s", req))
		}
	}
	if strings.TrimSpace(fPac) == "" {
		exitWithUsage("Unexpected empty value for -c")
	}

	if fVerbose {
		log.SetOutput(os.Stderr)
		verbose = true
	} else {
		log.SetOutput(io.Discard)
	}
	log.SetPrefix("")
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile | log.LUTC)
	log.Printf("Starting %s v%s", Name, Version)

	otto := pac.NewOttoEngine(
		pac.OttoLoader(pac.SmartLoader(fPac)),
	)
	if err := otto.Start(); err != nil {
		log.Panic(err)
	}
	defer otto.Stop()

	// Cache PAC decisions (keyed on host+path) so the JavaScript VM (which
	// serialises all callers under one lock) stays off the hot path. A
	// SIGHUP reload swaps the VM *and* flushes this cache, so edited PAC
	// files take effect immediately rather than after the TTL.
	finder := pac.NewCachingProxyFinder(otto, pac.WithProxyCacheTTL(fCacheTTL))
	initSignalNotify(&reloadManager{engine: otto, finder: finder})

	if fResolveURL != "" {
		do_resolve(otto)
		return
	}
	listen(finder)
}

// reloadManager reloads the PAC engine and clears cached decisions so a
// reloaded script's effects are observed without waiting for TTL expiry.
type reloadManager struct {
	engine *pac.OttoEngine
	finder *pac.CachingProxyFinder
}

func (m *reloadManager) Start() error { return m.engine.Start() }
func (m *reloadManager) Stop() error  { return m.engine.Stop() }
func (m *reloadManager) Reload() error {
	if err := m.engine.Reload(); err != nil {
		return err
	}
	m.finder.Invalidate("")
	return nil
}

func exitWithUsage(message string) {
	os.Stderr.WriteString(message)
	os.Stderr.WriteString("\n")
	flag.Usage()
	os.Exit(2) // the same exit code flag.Parse uses
}

func do_resolve(otto *pac.OttoEngine) {
	u, err := url.Parse(fResolveURL)
	if err != nil {
		log.Printf("Unable to parse resolve URL %q: %s", fResolveURL, err)
		os.Exit(1)
	}
	proxies, err := otto.FindProxyForURL(u)
	if err != nil {
		log.Printf("Error while trying to find proxy for URL %q: %s", fResolveURL, err)
		os.Exit(1)
	}
	for i := 0; i < len(proxies); i++ {
		fmt.Println(proxies[i])
	}
}

func listen(finder pac.ProxyFinder) {
	srv := &http.Server{
		Addr:              fListen,
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       60 * time.Second,
		Handler: newProxyHTTPHandler(
			finder,
			&pac.FirstItemSelector{},
			newNonProxyHTTPHandler(),
		),
	}
	log.Printf("Listening on %q", fListen)
	if err := srv.ListenAndServe(); err != nil {
		log.Panic(err)
	}
}
