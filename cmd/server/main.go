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
	"time"

	"dev-utilities/internal/config"
	"dev-utilities/internal/logging"
	"dev-utilities/internal/server"
	"dev-utilities/internal/version"
)

func main() {
	// Parse command line flags
	var (
		healthCheck = flag.Bool("health-check", false, "Perform health check and exit")
		help        = flag.Bool("help", false, "Show help information")
		showVersion = flag.Bool("version", false, "Show version information")
	)
	flag.Parse()

	// Handle help flag
	if *help {
		fmt.Println("Dev Utilities MCP Server")
		fmt.Println("Usage:")
		fmt.Println("  server [flags]")
		fmt.Println("")
		fmt.Println("Flags:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Handle version flag
	if *showVersion {
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

	// Handle health check flag (for Docker health checks)
	if *healthCheck {
		if err := performHealthCheck(); err != nil {
			log.Printf("Health check failed: %v", err)
			os.Exit(1)
		}
		fmt.Println("Health check passed")
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Setup structured logging
	logger := logging.New(cfg.Log.Level)

	logger.Info("Starting Dev Utilities MCP Server",
		"version", version.Get().Version,
		"port", cfg.Server.Port,
		"log_level", cfg.Log.Level,
		"auth_method", cfg.Auth.Method,
	)

	// Create and start server
	srv := server.New(cfg, logger)

	// Start server in a goroutine
	go func() {
		if err := srv.Start(); err != nil {
			logger.Error("Server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Received shutdown signal")

	// Give the server 30 seconds to shutdown gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	logger.Info("Server shutdown complete")
}

// performHealthCheck performs a health check against the running server
func performHealthCheck() error {
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	url := fmt.Sprintf("http://localhost:%s/health/live", port)
	
	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	resp, err := client.Get(url)
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

