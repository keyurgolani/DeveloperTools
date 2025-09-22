package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/keyurgolani/DeveloperTools/internal/config"
	"github.com/keyurgolani/DeveloperTools/internal/constants"
	"github.com/keyurgolani/DeveloperTools/internal/logging"
	"github.com/keyurgolani/DeveloperTools/internal/server"
	"github.com/keyurgolani/DeveloperTools/internal/validation"
)

func main() {
	specPath, verbose := parseFlags()
	printHeader()

	cfg := createConfig(*verbose)
	logger := logging.New(cfg.Log.Level)
	srv := server.New(cfg, logger)

	validator := createValidator(*specPath, srv)
	loadSpecification(validator, *specPath)

	runValidation(validator)
}

func parseFlags() (*string, *bool) {
	specPath := flag.String("spec", "api/openapi.yml", "Path to OpenAPI specification file")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	flag.Parse()
	return specPath, verbose
}

func printHeader() {
	fmt.Println("🔍 API Validation Tool")
	fmt.Println("======================")
}

func createConfig(verbose bool) *config.Config {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: constants.DefaultPort,
		},
		Log: config.LogConfig{
			Level: "info",
		},
	}

	if verbose {
		cfg.Log.Level = "debug"
	}

	return cfg
}

func createValidator(specPath string, srv *server.Server) *validation.APIValidator {
	validator, err := validation.NewAPIValidator(specPath, srv.GetRouter())
	if err != nil {
		fmt.Printf("❌ Failed to create validator: %v\n", err)
		os.Exit(1)
	}
	return validator
}

func loadSpecification(validator *validation.APIValidator, specPath string) {
	if _, err := os.Stat(specPath); err == nil {
		specData, err := os.ReadFile(specPath)
		if err != nil {
			fmt.Printf("❌ Failed to read spec file: %v\n", err)
			os.Exit(1)
		}

		if err := validator.LoadSpec(specData); err != nil {
			fmt.Printf("❌ Failed to load spec: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✅ Loaded OpenAPI specification from: %s\n", specPath)
	} else {
		fmt.Printf("⚠️  OpenAPI specification not found at: %s\n", specPath)
		fmt.Println("   Proceeding with basic validation...")
	}
}

func runValidation(validator *validation.APIValidator) {
	fmt.Println("\n🔍 Running API validation...")
	report := validator.GenerateValidationReport()

	validation.PrintValidationReport(report)

	if validation.IsValidationPassing(report) {
		fmt.Println("\n🎉 API validation completed successfully!")
		os.Exit(0)
	} else {
		fmt.Println("\n❌ API validation failed!")
		os.Exit(1)
	}
}
