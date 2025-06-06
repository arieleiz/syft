package main

import (
	"context"
	"fmt"
	"log"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/external"
)

// ConfigurableCataloger demonstrates how to use configuration in an external cataloger
type ConfigurableCataloger struct {
	includeLicenseContent bool
}

// Name returns the cataloger name
func (c *ConfigurableCataloger) Name() string {
	return "configurable-example-cataloger"
}

// Catalog demonstrates using configuration to control behavior
func (c *ConfigurableCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	fmt.Printf("ConfigurableCataloger running with license content inclusion: %v\n", c.includeLicenseContent)
	
	// This is just an example - in a real cataloger you would:
	// 1. Find relevant files using resolver.FilesByGlob() or resolver.FilesByPath()
	// 2. Parse those files to extract package information
	// 3. Use the configuration to control behavior (like license detection)
	
	return []pkg.Package{}, []artifact.Relationship{}, nil
}

// newConfigurableCataloger creates a cataloger that uses configuration
func newConfigurableCataloger(cfg external.Config) pkg.Cataloger {
	return &ConfigurableCataloger{
		// Use the license configuration to control behavior
		includeLicenseContent: cfg.LicenseConfig.IncludeContent != "none",
	}
}

func main() {
	fmt.Println("Registering configurable cataloger example...")

	// Register a cataloger that receives configuration
	err := external.RegisterCataloger(
		"configurable-example-cataloger", // cataloger name
		newConfigurableCataloger,         // factory function that receives config
		100,                              // high priority
		"example",                        // tags for selection
		"configurable",
	)
	if err != nil {
		log.Fatalf("Failed to register configurable cataloger: %v", err)
	}

	fmt.Println("Success: configurable cataloger registered!")
	fmt.Println()
	fmt.Println("This cataloger demonstrates:")
	fmt.Println("  - Receiving configuration from syft")
	fmt.Println("  - Using license configuration to control behavior")
	fmt.Println("  - External cataloger registration with config support")
	fmt.Println()
	fmt.Println("Available tags: example, configurable")
	fmt.Println("Usage: syft scan <target> --select example")
	fmt.Println("   Or: syft scan <target> --select configurable-example-cataloger")

	// Show that the cataloger is registered
	registered := external.ListRegisteredCatalogers()
	fmt.Printf("\nRegistered external catalogers: %v\n", registered)
}