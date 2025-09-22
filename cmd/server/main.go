package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/keyurgolani/DeveloperTools/internal/config"
	"github.com/keyurgolani/DeveloperTools/internal/constants"
	"github.com/keyurgolani/DeveloperTools/internal/logging"
	"github.com/keyurgolani/DeveloperTools/internal/server"
	"github.com/keyurgolani/DeveloperTools/internal/version"
)

func main() {
	flags := parseFlags()

	handleSpecialFlags(flags)

	cfg := loadConfiguration()
	logger := setupLogging(cfg)

	logStartupInfo(logger, cfg)

	srv := createAndStartServer(cfg, logger)

	waitForShutdownSignal(logger, srv)
}

// flags holds command line flag values.
type flags struct {
	healthCheck *bool
	help        *bool
	showVersion *bool
}

// parseFlags parses command line flags.
func parseFlags() flags {
	f := flags{
		healthCheck: flag.Bool("health-check", false, "Perform health check and exit"),
		help:        flag.Bool("help", false, "Show help information"),
		showVersion: flag.Bool("version", false, "Show version information"),
	}
	flag.Parse()
	return f
}

// handleSpecialFlags handles help, version, and health check flags.
func handleSpecialFlags(f flags) {
	if *f.help {
		showHelp()
	}

	if *f.showVersion {
		showVersion()
	}

	if *f.healthCheck {
		performHealthCheckAndExit()
	}
}

// showHelp displays help information and exits.
func showHelp() {
	fmt.Println("Dev Utilities MCP Server")
	fmt.Println("Usage:")
	fmt.Println("  server [flags]")
	fmt.Println("")
	fmt.Println("Flags:")
	flag.PrintDefaults()
	os.Exit(0)
}

// showVersion displays version information and exits.
func showVersion() {
	versionInfo := version.Get()
	fmt.Printf("%s v%s\n", versionInfo.Service, versionInfo.Version)
	if versionInfo.BuildDate != "unknown" {
		fmt.Printf("Build Date: %s\n", versionInfo.BuildDate)
	}
	if versionInfo.GitCommit != "unknown" {
		fmt.Printf("Git Commit: %s\n", versionInfo.GitCommit)
	}
	os.Exit(0)
}

// performHealthCheckAndExit performs health check and exits.
func performHealthCheckAndExit() {
	if err := performHealthCheck(); err != nil {
		log.Printf("Health check failed: %v", err)
		os.Exit(1)
	}
	fmt.Println("Health check passed")
	os.Exit(0)
}

// loadConfiguration loads and validates configuration.
func loadConfiguration() *config.Config {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	return cfg
}

// setupLogging creates and configures the logger.
func setupLogging(cfg *config.Config) *logging.Logger {
	return logging.New(cfg.Log.Level)
}

// logStartupInfo logs server startup information.
func logStartupInfo(logger *logging.Logger, cfg *config.Config) {
	logger.Info("Starting Dev Utilities MCP Server",
		"version", version.Get().Version,
		"port", cfg.Server.Port,
		"log_level", cfg.Log.Level,
		"auth_method", cfg.Auth.Method,
	)
}

// createAndStartServer creates and starts the server.
func createAndStartServer(cfg *config.Config, logger *logging.Logger) *server.Server {
	srv := server.New(cfg, logger)

	// Start server in a goroutine
	go func() {
		if err := srv.Start(); err != nil {
			logger.Error("Server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	return srv
}

// waitForShutdownSignal waits for shutdown signal and gracefully shuts down.
func waitForShutdownSignal(logger *logging.Logger, srv *server.Server) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Received shutdown signal")

	// Give the server time to shutdown gracefully
	ctx, cancel := context.WithTimeout(context.Background(), constants.DefaultShutdownTimeout)

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
		cancel()
		os.Exit(1)
	}

	cancel()
	logger.Info("Server shutdown complete")
}

// performHealthCheck performs a health check against the running server.
func performHealthCheck() error {
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	url := fmt.Sprintf("http://localhost:%s/health/live", port)

	client := &http.Client{
		Timeout: constants.DefaultGracefulTimeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), constants.DefaultGracefulTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to health endpoint: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("Failed to close response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	return nil
}
