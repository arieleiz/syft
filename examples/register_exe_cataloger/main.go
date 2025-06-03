package main

import (
	"context"
	"debug/pe"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// ExeVersionCataloger is a custom cataloger that extracts version information from Windows .exe files
type ExeVersionCataloger struct{}

// Name returns the cataloger name
func (c *ExeVersionCataloger) Name() string {
	return "exe-version-cataloger"
}

// Catalog finds .exe files and extracts their version information
func (c *ExeVersionCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship

	// Find all .exe files
	locations, err := resolver.FilesByGlob("**/*.exe")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find .exe files: %w", err)
	}

	for _, location := range locations {
		pkgs, rels, err := c.catalogExeFile(resolver, location)
		if err != nil {
			// Log error but continue processing other files
			log.Printf("Failed to catalog %s: %v", location.RealPath, err)
			continue
		}
		packages = append(packages, pkgs...)
		relationships = append(relationships, rels...)
	}

	return packages, relationships, nil
}

// catalogExeFile processes a single .exe file and extracts version information
func (c *ExeVersionCataloger) catalogExeFile(resolver file.Resolver, location file.Location) ([]pkg.Package, []artifact.Relationship, error) {
	contentReader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get file contents: %w", err)
	}
	defer internal.CloseAndLogError(contentReader, location.AccessPath)

	// Read the entire file content into memory (for PE parsing)
	content, err := io.ReadAll(contentReader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read file contents: %w", err)
	}

	// Parse the PE file to extract version information
	versionInfo, err := c.extractVersionFromPE(content)
	if err != nil {
		// Not a valid PE file or no version info, skip
		return nil, nil, nil
	}

	// Create package from version information
	p := pkg.Package{
		Name:      versionInfo.ProductName,
		Version:   versionInfo.ProductVersion,
		Type:      pkg.BinaryPkg, // Use binary package type
		Language:  "",            // Not language-specific
		FoundBy:   c.Name(),
		Locations: file.NewLocationSet(location),
		Metadata:  versionInfo, // Store detailed version info as metadata
	}

	// Create package-to-file relationship
	relationship := artifact.Relationship{
		From: p,
		To:   location.Coordinates,
		Type: artifact.ContainsRelationship,
	}

	return []pkg.Package{p}, []artifact.Relationship{relationship}, nil
}

// ExeVersionInfo holds version information extracted from a .exe file
type ExeVersionInfo struct {
	ProductName      string `json:"productName"`
	ProductVersion   string `json:"productVersion"`
	FileVersion      string `json:"fileVersion"`
	CompanyName      string `json:"companyName"`
	FileDescription  string `json:"fileDescription"`
	LegalCopyright   string `json:"legalCopyright"`
	InternalName     string `json:"internalName"`
	OriginalFilename string `json:"originalFilename"`
}

// extractVersionFromPE extracts version information from PE file content
func (c *ExeVersionCataloger) extractVersionFromPE(content []byte) (*ExeVersionInfo, error) {
	// Create a reader from the content
	reader := strings.NewReader(string(content))

	// Parse the PE file
	peFile, err := pe.NewFile(reader)
	if err != nil {
		return nil, fmt.Errorf("not a valid PE file: %w", err)
	}
	defer peFile.Close()

	// For this example, we'll extract basic information from the PE headers
	// In a real implementation, you would parse the VERSION_INFO resource
	// which contains detailed version information

	versionInfo := &ExeVersionInfo{
		ProductName:    "Unknown", // Default values
		ProductVersion: "0.0.0",
		FileVersion:    "0.0.0",
	}

	// Try to extract machine type and characteristics as basic info
	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		versionInfo.ProductName = "Windows Executable (x86)"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		versionInfo.ProductName = "Windows Executable (x64)"
	case pe.IMAGE_FILE_MACHINE_ARM:
		versionInfo.ProductName = "Windows Executable (ARM)"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		versionInfo.ProductName = "Windows Executable (ARM64)"
	default:
		versionInfo.ProductName = "Windows Executable"
	}

	// For demonstration, extract a version from the timestamp
	// In a real implementation, you would parse the VERSION_INFO resource
	timestamp := peFile.TimeDateStamp
	versionInfo.ProductVersion = fmt.Sprintf("1.0.%d", timestamp%10000)
	versionInfo.FileVersion = versionInfo.ProductVersion

	// NOTE: For a production implementation, you would need to:
	// 1. Parse the VERSION_INFO resource section
	// 2. Extract StringFileInfo and VarFileInfo
	// 3. Parse the version strings (ProductVersion, FileVersion, etc.)
	// 4. Handle different encodings and languages
	//
	// This would require implementing or using a library for Windows
	// resource parsing, which is beyond this example's scope.

	return versionInfo, nil
}

func main() {
	fmt.Println("Registering .exe version cataloger...")

	// Register the custom .exe cataloger with high priority
	err := task.RegisterSimpleCataloger(
		"exe-version-cataloger", // cataloger name
		func() pkg.Cataloger { // factory function
			return &ExeVersionCataloger{}
		},
		100,      // high priority (processed before built-ins)
		"binary", // tags for selection
		"windows",
		"executable",
		"version",
	)
	if err != nil {
		log.Fatalf("Failed to register .exe cataloger: %v", err)
	}

	fmt.Println("Success: .exe version cataloger registered!")
	fmt.Println()
	fmt.Println("The cataloger will now:")
	fmt.Println("  - Find all .exe files during SBOM generation")
	fmt.Println("  - Extract version information from PE headers")
	fmt.Println("  - Create packages with version metadata")
	fmt.Println("  - Work with existing Syft commands and APIs")
	fmt.Println()
	fmt.Println("Available tags: binary, windows, executable, version")
	fmt.Println("Usage: syft scan <target> --select binary")
	fmt.Println("   Or: syft scan <target> --select exe-version-cataloger")

	// Example: Test with a directory source (you would replace this with actual directory containing .exe files)
	// src, err := directorysource.NewFromPath("/path/to/windows/directory")
	// if err != nil {
	//     log.Fatalf("Failed to create source: %v", err)
	// }
	//
	// resolver, err := src.FileResolver(source.SquashedScope)
	// if err != nil {
	//     log.Fatalf("Failed to get file resolver: %v", err)
	// }
	//
	// cataloger := &ExeVersionCataloger{}
	// packages, _, err := cataloger.Catalog(context.Background(), resolver)
	// if err != nil {
	//     log.Fatalf("Failed to catalog: %v", err)
	// }
	//
	// fmt.Printf("Found %d .exe packages\n", len(packages))
	// for _, pkg := range packages {
	//     fmt.Printf("  %s v%s (%s)\n", pkg.Name, pkg.Version, pkg.Locations.ToSlice()[0].RealPath)
	// }

	// Show that the cataloger is registered
	registered := task.ListRegisteredCatalogers()
	fmt.Printf("\nRegistered external catalogers: %v\n", registered)
}
