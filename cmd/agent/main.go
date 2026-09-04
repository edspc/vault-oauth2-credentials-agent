// Command agent acquires, refreshes and stores OAuth2 credentials in
// HashiCorp Vault.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/edspc/vault-oauth2-credentials-agent/internal/agent"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/config"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/httpapi"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/metrics"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/refresher"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/tokenstore"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/vault"
)

// loginAttempts is how often the agent tries to authenticate to Vault at
// startup before giving up and letting the supervisor restart it.
const (
	loginAttempts = 3
	loginRetryGap = 2 * time.Second
)

// binaryName is how the agent identifies itself to a person running it.
const binaryName = "vault-oauth2-agent"

// version is stamped at build time with -ldflags "-X main.version=...". It
// stays "dev" for a plain `go build`, so an unstamped binary never claims to
// be a release.
var version = metrics.DefaultVersion

func main() {
	configPath := flag.String("config", envOr("CONFIG_PATH", "config.yaml"),
		"path to the configuration file")
	logLevel := flag.String("log-level", envOr("LOG_LEVEL", "info"),
		"log level: debug, info, warn or error")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(binaryName, version)
		return
	}

	logger, err := newLogger(*logLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	slog.SetDefault(logger)

	if err := run(*configPath, logger); err != nil {
		logger.Error("agent stopped", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(configPath string, logger *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	vaultClient, err := vault.New(vault.Config{
		Address:   cfg.Vault.Address,
		Namespace: cfg.Vault.Namespace,
		Timeout:   cfg.Vault.Timeout.Duration(),
		Auth: vault.AuthConfig{
			Method: cfg.Vault.Auth.Method,
			Token:  cfg.Vault.Auth.Token,
			AppRole: vault.AppRoleConfig{
				Mount:    cfg.Vault.Auth.AppRole.Mount,
				RoleID:   cfg.Vault.Auth.AppRole.RoleID,
				SecretID: cfg.Vault.Auth.AppRole.SecretID,
			},
			Kubernetes: vault.KubernetesConfig{
				Mount:   cfg.Vault.Auth.Kubernetes.Mount,
				Role:    cfg.Vault.Auth.Kubernetes.Role,
				JWTPath: cfg.Vault.Auth.Kubernetes.JWTPath,
			},
		},
	}, vault.WithLogger(logger))
	if err != nil {
		return err
	}
	if err := loginWithRetry(ctx, vaultClient, logger); err != nil {
		return err
	}

	entries, err := agent.BuildEntries(cfg, providerHTTPClient())
	if err != nil {
		return err
	}
	registry := agent.NewRegistry(entries)
	store := tokenstore.New(vaultClient)

	// With no metrics path configured, nothing is measured and no endpoint is
	// registered: a nil recorder makes every recording call a no-op.
	var recorder *metrics.Recorder
	var exporter http.Handler
	if cfg.Metrics.Enabled() {
		recorder = metrics.NewRecorder(entries)
		exporter = metrics.NewExporter(entries, registry, vaultClient, recorder,
			metrics.WithVersion(version))
		logger.Info("serving metrics", slog.String("path", cfg.Metrics.Path))
	}

	refresh := refresher.New(entries, store, registry, refresher.Config{
		Interval:     cfg.Refresh.Interval.Duration(),
		BeforeExpiry: cfg.Refresh.BeforeExpiry.Duration(),
		MaxBackoff:   cfg.Refresh.MaxBackoff.Duration(),
	}, refresher.WithLogger(logger), refresher.WithMetrics(recorder))

	api := httpapi.New(entries, store, registry, httpapi.Config{
		CallbackPath: cfg.Server.CallbackPath,
		MetricsPath:  cfg.Metrics.Path,
	},
		httpapi.WithLogger(logger),
		httpapi.WithReadyCheck(vaultClient.TokenValid),
		httpapi.WithMetrics(recorder, exporter))

	server := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           api.Handler(),
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout.Duration(),
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}

	var background sync.WaitGroup
	background.Add(2)
	go func() {
		defer background.Done()
		vaultClient.MaintainToken(ctx)
	}()
	go func() {
		defer background.Done()
		refresh.Run(ctx)
	}()

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("listening",
			slog.String("address", cfg.Server.Listen),
			slog.Int("entries", len(entries)))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	select {
	case err := <-serverErr:
		stop()
		background.Wait()
		if err != nil {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	case <-ctx.Done():
		logger.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout.Duration())
	defer cancel()
	shutdownErr := server.Shutdown(shutdownCtx)
	background.Wait()
	<-serverErr
	if shutdownErr != nil {
		return fmt.Errorf("shutdown http server: %w", shutdownErr)
	}
	return nil
}

// loginWithRetry authenticates to Vault, retrying a few times so that a
// restarting Vault does not immediately fail the agent.
func loginWithRetry(ctx context.Context, client *vault.Client, logger *slog.Logger) error {
	var err error
	for attempt := 1; attempt <= loginAttempts; attempt++ {
		if err = client.Login(ctx); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt < loginAttempts {
			logger.Warn("vault login failed, retrying",
				slog.Int("attempt", attempt),
				slog.String("error", err.Error()))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(loginRetryGap):
			}
		}
	}
	return fmt.Errorf("authenticate to vault: %w", err)
}

// providerHTTPClient is the HTTP client used for token endpoint calls.
func providerHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 4
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}
}

func newLogger(level string) (*slog.Logger, error) {
	var parsed slog.Level
	if err := parsed.UnmarshalText([]byte(strings.ToUpper(level))); err != nil {
		return nil, fmt.Errorf("invalid log level %q: %w", level, err)
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: parsed})), nil
}

func envOr(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return fallback
}
