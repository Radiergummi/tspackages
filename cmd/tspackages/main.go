// Command tspackages is a package registry that serves only its tailnet.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/server"
	"github.com/radiergummi/tspackages/internal/workdir"
	"tailscale.com/tsnet"
)

func main() {
	configPath := flag.String("config", "/etc/tspackages/config.yaml", "path to the configuration file")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn or error")
	logFormat := flag.String("log-format", "json", "log line format: json or text")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	v, c := buildVersion()
	if *showVersion {
		fmt.Println("tspackages", v, c)
		return
	}
	log, err := newLogger(os.Stderr, *logLevel, *logFormat)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tspackages:", err)
		os.Exit(2)
	}
	slog.SetDefault(log)
	metrics.SetBuildInfo(v, c)
	log.Info("starting", "version", v, "commit", c, "go", runtime.Version())

	if err := run(*configPath, log); err != nil {
		log.Error("tspackages failed", "error", err)
		os.Exit(1)
	}
}

func run(configPath string, log *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	// The state dir holds the node and TLS keys.
	if err := workdir.EnsurePrivateDir(cfg.Tailscale.StateDir); err != nil {
		return fmt.Errorf("tsnet state dir: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// One instance per work_dir: mirrors and key files are not shared.
	unlock, err := workdir.Lock(ctx, cfg.Storage.WorkDir, 60*time.Second, log)
	if err != nil {
		return err
	}
	defer unlock()

	// tsnet reads its credentials (tsnetEnv) from the environment itself.
	srv := &tsnet.Server{
		Hostname:      cfg.Tailscale.Hostname,
		Dir:           cfg.Tailscale.StateDir,
		AdvertiseTags: cfg.Tailscale.Tags,
		Logf:          logf(log, slog.LevelDebug),
		UserLogf:      logf(log, slog.LevelInfo),
	}
	defer srv.Close()
	if _, err := srv.Up(ctx); err != nil {
		return fmt.Errorf("join tailnet: %w", err)
	}
	scrubEnv(tsnetEnv)
	lc, err := srv.LocalClient()
	if err != nil {
		return err
	}
	// Build runs after Up, so the stores and the tailnet are both ready here.
	handler, start, err := server.Build(ctx, cfg, lc, log, server.Hooks{})
	if err != nil {
		return err
	}
	scrubEnv(cfg.EnvRefs())
	ln, err := srv.ListenTLS("tcp", ":443")
	if err != nil {
		return err
	}
	// Registered after unlock, so it runs first: the background loops write
	// to work_dir and must stop before another instance may take the lock.
	loopsDone := make(chan struct{})
	go func() { defer close(loopsDone); start(ctx) }()
	defer func() { stop(); <-loopsDone }()

	// No WriteTimeout: artifact downloads can be large.
	hs := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	log.Info("serving", "hostname", cfg.Tailscale.Hostname)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	stop() // a second signal now terminates immediately
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := hs.Shutdown(shutdownCtx); err != nil {
		log.Warn("graceful shutdown timed out; closing open connections", "error", err)
		hs.Close()
	}
	return nil
}

// newLogger returns the process logger for a -log-level and -log-format.
func newLogger(w io.Writer, level, format string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid -log-level %q", level)
	}
	opts := &slog.HandlerOptions{Level: l}
	switch format {
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	}
	return nil, fmt.Errorf("invalid -log-format %q (use json or text)", format)
}

// tsnetEnv holds tsnet's credentials; it reads them itself during Up.
var tsnetEnv = []string{"TS_AUTHKEY", "TS_AUTH_KEY", "TS_CLIENT_SECRET", "TS_ID_TOKEN"}

// scrubEnv unsets names so git and ssh never inherit them, except variables
// the process itself needs (PATH, HOME, USER, TMPDIR, LANG, LC_*), which a
// ${env:} reference may name too.
func scrubEnv(names []string) {
	for _, n := range names {
		switch {
		case n == "PATH", n == "HOME", n == "USER", n == "TMPDIR", n == "LANG", strings.HasPrefix(n, "LC_"):
		default:
			os.Unsetenv(n)
		}
	}
}

// logf adapts tsnet's printf-style loggers to slog.
func logf(log *slog.Logger, level slog.Level) func(string, ...any) {
	return func(format string, args ...any) {
		if log.Enabled(context.Background(), level) {
			log.Log(context.Background(), level, fmt.Sprintf(format, args...), "component", "tsnet")
		}
	}
}
