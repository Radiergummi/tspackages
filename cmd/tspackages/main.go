// Command tspackages is a package registry that serves only its tailnet.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/server"
	"tailscale.com/tsnet"
)

func main() {
	configPath := flag.String("config", "/etc/tspackages/config.yaml", "path to the configuration file")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn or error")
	flag.Parse()

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "tspackages: invalid -log-level %q\n", *logLevel)
		os.Exit(2)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

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
	if cfg.Tailscale.StateDir == "" {
		return errors.New("tailscale.state_dir is required")
	}
	if err := server.EnsurePrivateDir(cfg.Tailscale.StateDir); err != nil {
		return fmt.Errorf("tsnet state dir: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// tsnet reads TS_AUTHKEY itself.
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
	// Keep the auth key out of the environment git and ssh inherit.
	os.Unsetenv("TS_AUTHKEY")
	lc, err := srv.LocalClient()
	if err != nil {
		return err
	}
	// Build runs after Up, so the stores and the tailnet are both ready here.
	handler, start, err := server.Build(ctx, cfg, lc, log, server.Hooks{})
	if err != nil {
		return err
	}
	for _, name := range cfg.EnvRefs() {
		os.Unsetenv(name)
	}
	ln, err := srv.ListenTLS("tcp", ":443")
	if err != nil {
		return err
	}
	start(ctx)

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
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := hs.Shutdown(shutdownCtx); err != nil {
		log.Warn("graceful shutdown timed out; closing open connections", "error", err)
		hs.Close()
	}
	return nil
}

// logf adapts tsnet's printf-style loggers to slog.
func logf(log *slog.Logger, level slog.Level) func(string, ...any) {
	return func(format string, args ...any) {
		if log.Enabled(context.Background(), level) {
			log.Log(context.Background(), level, fmt.Sprintf(format, args...), "component", "tsnet")
		}
	}
}
