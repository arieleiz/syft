package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/acobaugh/osrelease"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

// parseGardenLinux is a custom parser for SAP Garden Linux
// It checks for Garden Linux specific identifiers in os-release files
func parseGardenLinux(contents string) (*linux.Release, error) {
	values, err := osrelease.ReadString(contents)
	if err != nil {
		return nil, fmt.Errorf("unable to read os-release file: %w", err)
	}

	// Check if this is Garden Linux specifically
	id := strings.ToLower(values["ID"])
	name := values["NAME"]
	prettyName := values["PRETTY_NAME"]

	// Garden Linux identification patterns
	isGardenLinux := id == "gardenlinux" ||
		strings.Contains(strings.ToLower(name), "garden") ||
		strings.Contains(strings.ToLower(prettyName), "garden")

	if !isGardenLinux {
		// Not Garden Linux, return nil to let other parsers try
		return nil, nil
	}

	// Parse ID_LIKE for package manager compatibility
	var idLike []string
	for _, s := range strings.Split(values["ID_LIKE"], " ") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		idLike = append(idLike, s)
	}

	// Ensure Garden Linux is marked as debian-like for package cataloging
	if len(idLike) == 0 {
		idLike = []string{"debian"}
	} else {
		// Add debian if not already present
		hasDebian := false
		for _, like := range idLike {
			if like == "debian" {
				hasDebian = true
				break
			}
		}
		if !hasDebian {
			idLike = append(idLike, "debian")
		}
	}

	return &linux.Release{
		PrettyName:       prettyName,
		Name:             name,
		ID:               id,
		IDLike:           idLike,
		Version:          values["VERSION"],
		VersionID:        values["VERSION_ID"],
		VersionCodename:  values["VERSION_CODENAME"],
		BuildID:          values["BUILD_ID"],
		ImageID:          values["IMAGE_ID"],
		ImageVersion:     values["IMAGE_VERSION"],
		Variant:          values["VARIANT"],
		VariantID:        values["VARIANT_ID"],
		HomeURL:          values["HOME_URL"],
		SupportURL:       values["SUPPORT_URL"],
		BugReportURL:     values["BUG_REPORT_URL"],
		PrivacyPolicyURL: values["PRIVACY_POLICY_URL"],
		CPEName:          values["CPE_NAME"],
		SupportEnd:       values["SUPPORT_END"],
	}, nil
}

func main() {
	// Register Garden Linux parser with high priority
	// This will be checked before the default os-release parser
	err := linux.RegisterParser("/etc/os-release", parseGardenLinux, 100)
	if err != nil {
		log.Fatalf("Failed to register Garden Linux parser: %v", err)
	}

	// Also register for the alternative os-release location
	err = linux.RegisterParser("/usr/lib/os-release", parseGardenLinux, 100)
	if err != nil {
		log.Fatalf("Failed to register Garden Linux parser: %v", err)
	}

	fmt.Println("Garden Linux parser registered successfully!")
	fmt.Println("Now when Syft scans Garden Linux systems:")
	fmt.Println("1. It will correctly identify the distro as Garden Linux")
	fmt.Println("2. It will use existing DEB catalogers (due to ID_LIKE=[\"debian\"])")
	fmt.Println("3. All package detection will work normally")

	// Example: Test with a directory source (you would replace this with actual Garden Linux system)
	// src, err := directorysource.NewFromPath("/path/to/garden/linux/root")
	// if err != nil {
	//     log.Fatalf("Failed to create source: %v", err)
	// }
	// 
	// release := linux.IdentifyRelease(src.FileResolver(source.SquashedScope))
	// if release != nil {
	//     fmt.Printf("Detected distro: %s\n", release.String())
	//     fmt.Printf("ID: %s, ID_LIKE: %v\n", release.ID, release.IDLike)
	// }
}