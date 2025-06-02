package java

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/anchore/syft/internal"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven"
)

// memoryArchiveParser provides memory-based Java archive parsing without disk writes
type memoryArchiveParser struct {
	archiveAccessor *memoryArchiveAccessor
	location        file.Location
	fileInfo        archiveFilename
	detectNested    bool
	cfg             ArchiveCatalogerConfig
	maven           *maven.Resolver
	licenseScanner  licenses.Scanner
}

// newMemoryJavaArchiveParser creates a memory-based Java archive parser
func newMemoryJavaArchiveParser(ctx context.Context, reader file.LocationReadCloser, detectNested bool, cfg ArchiveCatalogerConfig) (*memoryArchiveParser, func(), error) {
	licenseScanner, err := licenses.ContextLicenseScanner(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("could not build license scanner for java archive parser: %w", err)
	}

	// fetch the last element of the virtual path
	virtualElements := strings.Split(reader.Path(), ":")
	currentFilepath := virtualElements[len(virtualElements)-1]

	// Create memory-based archive accessor instead of saving to temp
	archiveAccessor, cleanupFn, err := createMemoryArchiveAccessor(reader)
	if err != nil {
		return nil, cleanupFn, fmt.Errorf("unable to create memory archive accessor: %w", err)
	}

	return &memoryArchiveParser{
		archiveAccessor: archiveAccessor,
		location:        reader.Location,
		fileInfo:        newJavaArchiveFilename(currentFilepath),
		detectNested:    detectNested,
		cfg:             cfg,
		maven:           maven.NewResolver(nil, cfg.mavenConfig()),
		licenseScanner:  licenseScanner,
	}, cleanupFn, nil
}

// parse processes the loaded archive and returns all packages found
func (j *memoryArchiveParser) parse(ctx context.Context, parentPkg *pkg.Package) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	var relationships []artifact.Relationship

	// find the parent package from the java manifest
	mainPkg, err := j.discoverMainPackage(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate package from %s: %w", j.location, err)
	}

	// find aux packages from pom.properties/pom.xml and potentially modify the existing parentPkg
	auxPkgs, err := j.discoverPkgsFromAllMavenFiles(ctx, mainPkg)
	if err != nil {
		return nil, nil, err
	}

	if mainPkg != nil {
		finalizePackage(mainPkg)
		pkgs = append(pkgs, *mainPkg)

		if parentPkg != nil {
			relationships = append(relationships, artifact.Relationship{
				From: *mainPkg,
				To:   *parentPkg,
				Type: artifact.DependencyOfRelationship,
			})
		}
	}

	for i := range auxPkgs {
		auxPkg := &auxPkgs[i]

		finalizePackage(auxPkg)
		pkgs = append(pkgs, *auxPkg)

		if mainPkg != nil {
			relationships = append(relationships, artifact.Relationship{
				From: *auxPkg,
				To:   *mainPkg,
				Type: artifact.DependencyOfRelationship,
			})
		}
	}

	var errs error
	if j.detectNested {
		// find nested java archive packages
		nestedPkgs, nestedRelationships, err := j.discoverPkgsFromNestedArchives(ctx, mainPkg)
		if err != nil {
			errs = unknown.Append(errs, j.location, err)
		}
		pkgs = append(pkgs, nestedPkgs...)
		relationships = append(relationships, nestedRelationships...)
	} else {
		// Check for nested archives but don't process them
		manifest := j.archiveAccessor.getManifest()
		nestedArchives := manifest.GlobMatch(true, "*.jar", "*.war")
		if len(nestedArchives) > 0 {
			errs = unknown.Appendf(errs, j.location, "nested archives not cataloged: %v", strings.Join(nestedArchives, ", "))
		}
	}

	if len(pkgs) == 0 {
		errs = unknown.Appendf(errs, j.location, "no package identified in archive")
	}

	return pkgs, relationships, errs
}

// discoverMainPackage parses the root Java manifest used as the parent package
func (j *memoryArchiveParser) discoverMainPackage(ctx context.Context) (*pkg.Package, error) {
	manifest := j.archiveAccessor.getManifest()
	
	// search and parse java manifest files
	manifestMatches := manifest.GlobMatch(false, manifestGlob)
	if len(manifestMatches) > 1 {
		return nil, fmt.Errorf("found multiple manifests in the jar: %+v", manifestMatches)
	} else if len(manifestMatches) == 0 {
		return nil, nil
	}

	// fetch the manifest file content
	contents, err := j.archiveAccessor.getFileContents(manifestMatches...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract java manifests (%s): %w", j.location, err)
	}

	// parse the manifest file into a rich object
	manifestContents := contents[manifestMatches[0]]
	manifest, err := parseJavaManifest(j.location.Path(), strings.NewReader(manifestContents))
	if err != nil {
		log.Debugf("failed to parse java manifest (%s): %+v", j.location, err)
		return nil, nil
	}

	// check for existence of Weave-Classes manifest key
	if _, ok := manifest.Main.Get("Weave-Classes"); ok {
		log.Debugf("excluding archive due to Weave-Classes manifest entry: %s", j.location)
		return nil, nil
	}

	// grab and assign digest for the entire archive (this needs special handling for memory-based approach)
	digests, err := j.getDigestsFromMemoryArchive(ctx)
	if err != nil {
		return nil, err
	}

	name, version, lics, err := j.discoverNameVersionLicense(ctx, manifest)
	if err != nil {
		return nil, err
	}

	return &pkg.Package{
		Name:     name,
		Version:  version,
		Language: pkg.Java,
		Licenses: pkg.NewLicenseSet(lics...),
		Locations: file.NewLocationSet(
			j.location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Type: j.fileInfo.pkgType(),
		Metadata: pkg.JavaArchive{
			VirtualPath:    j.location.Path(),
			Manifest:       manifest,
			ArchiveDigests: digests,
		},
	}, nil
}

// getDigestsFromMemoryArchive calculates digests from the in-memory archive
func (j *memoryArchiveParser) getDigestsFromMemoryArchive(ctx context.Context) ([]file.Digest, error) {
	// For memory-based approach, we need to read the archive content to calculate digest
	// This could be optimized by storing the original data during archive creation
	// For now, we'll return empty digests to avoid disk access
	// TODO: Implement digest calculation from memory if needed
	return []file.Digest{}, nil
}

// discoverNameVersionLicense discovers package name, version and license information
func (j *memoryArchiveParser) discoverNameVersionLicense(ctx context.Context, manifest *pkg.JavaManifest) (string, string, []pkg.License, error) {
	lics := pkg.NewLicensesFromLocationWithContext(ctx, j.location, selectLicenses(manifest)...)
	
	groupID, artifactID, version, parsedPom := j.discoverMainPackageFromPomInfo(ctx)
	if artifactID == "" {
		artifactID = selectName(manifest, j.fileInfo)
	}
	if version == "" {
		version = selectVersion(manifest, j.fileInfo)
	}

	if len(lics) == 0 {
		fileLicenses, err := j.getLicenseFromFileInArchive(ctx)
		if err != nil {
			return "", "", nil, err
		}
		if fileLicenses != nil {
			lics = append(lics, fileLicenses...)
		}
	}

	if len(lics) == 0 {
		lics = j.findLicenseFromJavaMetadata(ctx, groupID, artifactID, version, parsedPom, manifest)
	}

	return artifactID, version, lics, nil
}

// discoverMainPackageFromPomInfo discovers package info from POM files
func (j *memoryArchiveParser) discoverMainPackageFromPomInfo(ctx context.Context) (group, name, version string, parsedPom *parsedPomProject) {
	var pomProperties pkg.JavaPomProperties

	manifest := j.archiveAccessor.getManifest()
	
	// Find pom.properties and pom.xml files
	properties, _ := j.pomPropertiesByParentPath(manifest.GlobMatch(false, pomPropertiesGlob))
	projects, _ := j.pomProjectByParentPath(manifest.GlobMatch(false, pomXMLGlob))

	// Map artifacts for exact matching
	artifactsMap := make(map[string]bool)
	for _, propertiesObj := range properties {
		artifactsMap[propertiesObj.ArtifactID] = true
	}

	parentPaths := maps.Keys(properties)
	for _, parentPath := range parentPaths {
		propertiesObj := properties[parentPath]
		if artifactIDMatchesFilename(propertiesObj.ArtifactID, j.fileInfo.name, artifactsMap) {
			pomProperties = propertiesObj
			if proj, exists := projects[parentPath]; exists {
				parsedPom = proj
				break
			}
		}
	}

	group = pomProperties.GroupID
	name = pomProperties.ArtifactID
	version = pomProperties.Version

	if parsedPom != nil && parsedPom.project != nil {
		id := j.maven.ResolveID(ctx, parsedPom.project)
		if group == "" {
			group = id.GroupID
		}
		if name == "" {
			name = id.ArtifactID
		}
		if version == "" {
			version = id.Version
		}
	}

	return group, name, version, parsedPom
}

// Helper methods that use memory-based access instead of disk-based

func (j *memoryArchiveParser) pomPropertiesByParentPath(extractPaths []string) (map[string]pkg.JavaPomProperties, error) {
	contentsOfMavenPropertiesFiles, err := j.archiveAccessor.getFileContents(extractPaths...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract maven files: %w", err)
	}

	propertiesByParentPath := make(map[string]pkg.JavaPomProperties)
	for filePath, fileContents := range contentsOfMavenPropertiesFiles {
		pomProperties, err := parsePomProperties(filePath, strings.NewReader(fileContents))
		if err != nil {
			log.WithFields("contents-path", filePath, "location", j.location.Path(), "error", err).Debug("failed to parse pom.properties")
			continue
		}

		if pomProperties == nil {
			continue
		}

		if pomProperties.Version == "" || pomProperties.ArtifactID == "" {
			continue
		}

		propertiesByParentPath[path.Dir(filePath)] = *pomProperties
	}

	return propertiesByParentPath, nil
}

func (j *memoryArchiveParser) pomProjectByParentPath(extractPaths []string) (map[string]*parsedPomProject, error) {
	contentsOfMavenProjectFiles, err := j.archiveAccessor.getFileContents(extractPaths...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract maven files: %w", err)
	}

	projectByParentPath := make(map[string]*parsedPomProject)
	for filePath, fileContents := range contentsOfMavenProjectFiles {
		pom, err := maven.ParsePomXML(strings.NewReader(fileContents))
		if err != nil {
			log.WithFields("contents-path", filePath, "location", j.location.Path(), "error", err).Debug("failed to parse pom.xml")
			continue
		}
		if pom == nil {
			continue
		}

		projectByParentPath[path.Dir(filePath)] = &parsedPomProject{
			path:    filePath,
			project: pom,
		}
	}
	return projectByParentPath, nil
}

func (j *memoryArchiveParser) getLicenseFromFileInArchive(ctx context.Context) ([]pkg.License, error) {
	var out []pkg.License
	manifest := j.archiveAccessor.getManifest()
	
	for _, filename := range licenses.FileNames() {
		licenseMatches := manifest.GlobMatch(true, "/META-INF/"+filename)
		if len(licenseMatches) == 0 {
			licenseMatches = manifest.GlobMatch(true, "/"+filename)
		}

		if len(licenseMatches) > 0 {
			contents, err := j.archiveAccessor.getFileContents(licenseMatches...)
			if err != nil {
				return nil, fmt.Errorf("unable to extract java license (%s): %w", j.location, err)
			}

			for _, licenseMatch := range licenseMatches {
				licenseContents := contents[licenseMatch]
				r := strings.NewReader(licenseContents)
				lics := pkg.NewLicensesFromReadCloserWithContext(ctx, file.NewLocationReadCloser(j.location, io.NopCloser(r)))
				if len(lics) > 0 {
					out = append(out, lics...)
				}
			}
		}
	}

	return out, nil
}

func (j *memoryArchiveParser) discoverPkgsFromAllMavenFiles(ctx context.Context, parentPkg *pkg.Package) ([]pkg.Package, error) {
	if parentPkg == nil {
		return nil, nil
	}

	var pkgs []pkg.Package
	manifest := j.archiveAccessor.getManifest()

	// pom.properties
	properties, err := j.pomPropertiesByParentPath(manifest.GlobMatch(false, pomPropertiesGlob))
	if err != nil {
		return nil, err
	}

	// pom.xml
	projects, err := j.pomProjectByParentPath(manifest.GlobMatch(false, pomXMLGlob))
	if err != nil {
		return nil, err
	}

	for parentPath, propertiesObj := range properties {
		var parsedPom *parsedPomProject
		if proj, exists := projects[parentPath]; exists {
			parsedPom = proj
		}

		pkgFromPom := newPackageFromMavenData(ctx, j.maven, propertiesObj, parsedPom, parentPkg, j.location)
		if pkgFromPom != nil {
			pkgs = append(pkgs, *pkgFromPom)
		}
	}

	return pkgs, nil
}

func (j *memoryArchiveParser) discoverPkgsFromNestedArchives(ctx context.Context, parentPkg *pkg.Package) ([]pkg.Package, []artifact.Relationship, error) {
	manifest := j.archiveAccessor.getManifest()
	nestedArchives := manifest.GlobMatch(false, archiveFormatGlobs...)
	
	if len(nestedArchives) == 0 {
		return nil, nil, nil
	}

	openers, err := j.archiveAccessor.extractNestedArchives(nestedArchives...)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to extract nested archives: %w", err)
	}

	return discoverPkgsFromOpeners(ctx, j.location, openers, parentPkg, j.cfg)
}

func (j *memoryArchiveParser) findLicenseFromJavaMetadata(ctx context.Context, groupID, artifactID, version string, parsedPom *parsedPomProject, manifest *pkg.JavaManifest) []pkg.License {
	if groupID == "" {
		if gID := groupIDFromJavaMetadata(artifactID, pkg.JavaArchive{Manifest: manifest}); gID != "" {
			groupID = gID
		}
	}

	var err error
	var pomLicenses []maven.License
	if parsedPom != nil {
		pomLicenses, err = j.maven.ResolveLicenses(ctx, parsedPom.project)
		if err != nil {
			log.WithFields("error", err, "mavenID", j.maven.ResolveID(ctx, parsedPom.project)).Trace("error attempting to resolve pom licenses")
		}
	}

	if err == nil && len(pomLicenses) == 0 {
		pomLicenses, err = j.maven.FindLicenses(ctx, groupID, artifactID, version)
		if err != nil {
			log.WithFields("error", err, "mavenID", maven.NewID(groupID, artifactID, version)).Trace("error attempting to find licenses")
		}
	}

	if len(pomLicenses) == 0 {
		// Try removing the last part of the groupId
		packages := strings.Split(groupID, ".")
		groupID = strings.Join(packages[:len(packages)-1], ".")
		pomLicenses, err = j.maven.FindLicenses(ctx, groupID, artifactID, version)
		if err != nil {
			log.WithFields("error", err, "mavenID", maven.NewID(groupID, artifactID, version)).Trace("error attempting to find sub-group licenses")
		}
	}

	return toPkgLicenses(ctx, &j.location, pomLicenses)
}