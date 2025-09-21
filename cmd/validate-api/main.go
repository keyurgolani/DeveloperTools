package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"dev-utilities/internal/config"
	"dev-utilities/internal/logging"
	"dev-utilities/internal/server"
	"dev-utilities/internal/validation"
)

func main() {
	var (
		specPath = flag.String("spec", "api/openapi.yml", "Path to OpenAPI specification file")
		verbose  = flag.Bool("verbose", false, "Enable verbose output")
	)
	flag.Parse()

	fmt.Println("🔍 API Validation Tool")
	fmt.Println("======================")

	// Load configuration
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: 8080,
		},
		Log: config.LogConfig{
			Level: "info",
		},
	}

	if *verbose {
		cfg.Log.Level = "debug"
	}

	// Create logger
	logger := logging.New(cfg.Log.Level)

	// Create server instance
	srv := server.New(cfg, logger)

	// Create API validator
	validator, err := validation.NewAPIValidator(*specPath, srv.GetRouter())
	if err != nil {
		fmt.Printf("❌ Failed to create validator: %v\n", err)
		os.Exit(1)
	}

	// Load OpenAPI specification
	if _, err := os.Stat(*specPath); err == nil {
		specData, err := ioutil.ReadFile(*specPath)
		if err != nil {
			fmt.Printf("❌ Failed to read spec file: %v\n", err)
			os.Exit(1)
		}

		if err := validator.LoadSpec(specData); err != nil {
			fmt.Printf("❌ Failed to load spec: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✅ Loaded OpenAPI specification from: %s\n", *specPath)
	} else {
		fmt.Printf("⚠️  OpenAPI specification not found at: %s\n", *specPath)
		fmt.Println("   Proceeding with basic validation...")
	}

	// Generate validation report
	fmt.Println("\n🔍 Running API validation...")
	report := validator.GenerateValidationReport()

	// Print detailed report
	validation.PrintValidationReport(report)

	// Exit with appropriate code
	if validation.IsValidationPassing(report) {
		fmt.Println("\n🎉 API validation completed successfully!")
		os.Exit(0)
	} else {
		fmt.Println("\n❌ API validation failed!")
		os.Exit(1)
	}
}