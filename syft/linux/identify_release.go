package linux

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/acobaugh/osrelease"
	"github.com/google/go-cmp/cmp"

	"github.com/anchore/go-logger"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

// ParseFunc represents a function that parses distro release information from file contents.
// It returns a Release or nil if the content cannot be parsed by this parser.
type ParseFunc func(string) (*Release, error)

// parseEntry represents a single distro detection method
type parseEntry struct {
	path     string    // file path to check
	fn       ParseFunc // function to parse the file contents
	priority int       // higher priority entries are checked first (default: 0)
}

// Registry manages distro detection parsers and allows external registration
type Registry struct {
	mu      sync.RWMutex
	entries []parseEntry
}

// DefaultRegistry is the global registry used by IdentifyRelease
var DefaultRegistry = NewRegistry()

// NewRegistry creates a new parser registry with built-in parsers
func NewRegistry() *Registry {
	r := &Registry{}
	r.registerBuiltins()
	return r
}

// RegisterParser allows external registration of custom distro parsers.
// Higher priority parsers are checked first. Built-in parsers have priority 0.
// Returns an error if the parser is nil.
func (r *Registry) RegisterParser(path string, parser ParseFunc, priority int) error {
	if parser == nil {
		return fmt.Errorf("parser cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.entries = append(r.entries, parseEntry{
		path:     path,
		fn:       parser,
		priority: priority,
	})

	// Sort by priority (highest first), then by path for deterministic order
	sort.Slice(r.entries, func(i, j int) bool {
		if r.entries[i].priority != r.entries[j].priority {
			return r.entries[i].priority > r.entries[j].priority
		}
		return r.entries[i].path < r.entries[j].path
	})

	return nil
}

// GetParsers returns a copy of the current parser entries (thread-safe)
func (r *Registry) GetParsers() []parseEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return a copy to prevent external mutation
	result := make([]parseEntry, len(r.entries))
	copy(result, r.entries)
	return result
}

// registerBuiltins adds the default built-in parsers
func (r *Registry) registerBuiltins() {
	builtins := []parseEntry{
		{
			// most distros provide a link at this location
			path: "/etc/os-release",
			fn:   parseOsRelease,
		},
		{
			// standard location for rhel & debian distros
			path: "/usr/lib/os-release",
			fn:   parseOsRelease,
		},
		{
			// check for centos:6
			path: "/etc/system-release-cpe",
			fn:   parseSystemReleaseCPE,
		},
		{
			// last ditch effort for determining older centos version distro information
			path: "/etc/redhat-release",
			fn:   parseRedhatRelease,
		},
		// IMPORTANT! checking busybox must be last since other distros contain the busybox binary
		{
			// check for busybox
			path:     "/bin/busybox",
			fn:       parseBusyBox,
			priority: -1000, // ensure busybox is checked last
		},
	}

	r.entries = append(r.entries, builtins...)
}

// RegisterParser is a convenience function for registering parsers with the default registry
func RegisterParser(path string, parser ParseFunc, priority int) error {
	return DefaultRegistry.RegisterParser(path, parser, priority)
}

// legacy type alias for backward compatibility
type parseFunc func(string) (*Release, error)

// IdentifyRelease parses distro-specific files to discover and raise linux distribution release details.
// It uses the default registry which includes built-in parsers and any externally registered parsers.
func IdentifyRelease(resolver file.Resolver) *Release {
	return DefaultRegistry.IdentifyRelease(resolver)
}

// IdentifyRelease parses distro-specific files using this registry's parsers.
func (r *Registry) IdentifyRelease(resolver file.Resolver) *Release {
	logger := log.Nested("operation", "identify-release")
	entries := r.GetParsers() // thread-safe copy

	for _, entry := range entries {
		locations, err := resolver.FilesByPath(entry.path)
		if err != nil {
			logger.WithFields("error", err, "path", entry.path).Trace("unable to get path")
			continue
		}

		for _, location := range locations {
			release := tryParseReleaseInfo(resolver, location, logger, entry)
			if release != nil {
				return release
			}
		}
	}

	return nil
}

func tryParseReleaseInfo(resolver file.Resolver, location file.Location, logger logger.Logger, entry parseEntry) *Release {
	contentReader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		logger.WithFields("error", err, "path", location.RealPath).Trace("unable to get contents")
		return nil
	}
	defer internal.CloseAndLogError(contentReader, location.AccessPath)

	content, err := io.ReadAll(contentReader)
	if err != nil {
		logger.WithFields("error", err, "path", location.RealPath).Trace("unable to read contents")
		return nil
	}

	release, err := entry.fn(string(content))
	if err != nil {
		logger.WithFields("error", err, "path", location.RealPath).Trace("unable to parse contents")
		return nil
	}

	return release
}

func parseOsRelease(contents string) (*Release, error) {
	values, err := osrelease.ReadString(contents)
	if err != nil {
		return nil, fmt.Errorf("unable to read os-release file: %w", err)
	}

	var idLike []string
	for _, s := range strings.Split(values["ID_LIKE"], " ") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		idLike = append(idLike, s)
	}

	r := Release{
		PrettyName:       values["PRETTY_NAME"],
		Name:             values["NAME"],
		ID:               values["ID"],
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
	}

	// don't allow for empty contents to result in a Release object being created
	if cmp.Equal(r, Release{}) {
		return nil, nil
	}

	return &r, nil
}

var busyboxVersionMatcher = regexp.MustCompile(`BusyBox v[\d.]+`)

func parseBusyBox(contents string) (*Release, error) {
	matches := busyboxVersionMatcher.FindAllString(contents, -1)
	for _, match := range matches {
		parts := strings.Split(match, " ")
		version := strings.ReplaceAll(parts[1], "v", "")

		return simpleRelease(match, "busybox", version, ""), nil
	}
	return nil, nil
}

// example CPE: cpe:/o:centos:linux:6:GA
var systemReleaseCpeMatcher = regexp.MustCompile(`cpe:\/o:(.*?):.*?:(.*?):.*?$`)

// parseSystemReleaseCPE parses the older centos (6) file to determine distro metadata
func parseSystemReleaseCPE(contents string) (*Release, error) {
	matches := systemReleaseCpeMatcher.FindAllStringSubmatch(contents, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		return simpleRelease(match[1], strings.ToLower(match[1]), match[2], match[0]), nil
	}
	return nil, nil
}

// example: "CentOS release 6.10 (Final)"
var redhatReleaseMatcher = regexp.MustCompile(`(?P<name>.*?)\srelease\s(?P<version>(?P<versionid>\d\.\d+).*)`)

// parseRedhatRelease is a fallback parsing method for determining distro information in older redhat versions
func parseRedhatRelease(contents string) (*Release, error) {
	contents = strings.TrimSpace(contents)
	matches := internal.MatchNamedCaptureGroups(redhatReleaseMatcher, contents)
	name := matches["name"]
	version := matches["version"]
	versionID := matches["versionid"]
	if name == "" || versionID == "" {
		return nil, nil
	}

	id := strings.ToLower(name)
	switch {
	case strings.HasPrefix(id, "red hat enterprise linux"):
		id = "rhel"
	case strings.HasPrefix(id, "centos"):
		// ignore the parenthetical version information
		version = versionID
	}

	return &Release{
		PrettyName: contents,
		Name:       name,
		ID:         id,
		IDLike:     []string{id},
		Version:    version,
		VersionID:  versionID,
	}, nil
}

func simpleRelease(prettyName, name, version, cpe string) *Release {
	return &Release{
		PrettyName: prettyName,
		Name:       name,
		ID:         name,
		IDLike:     []string{name},
		Version:    version,
		VersionID:  version,
		CPEName:    cpe,
	}
}
