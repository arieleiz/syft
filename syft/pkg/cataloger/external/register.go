package external

import (
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/pkg"
)

// Config provides configuration for external catalogers that need
// access to syft's cataloging configuration options.
type Config struct {
	// ComplianceConfig holds compliance-related configuration
	ComplianceConfig cataloging.ComplianceConfig
	// SearchConfig configures how files are searched and indexed
	SearchConfig cataloging.SearchConfig
	// RelationshipsConfig configures relationship analysis
	RelationshipsConfig cataloging.RelationshipsConfig
	// DataGenerationConfig configures what data to generate during cataloging
	DataGenerationConfig cataloging.DataGenerationConfig
	// LicenseConfig configures license detection behavior
	LicenseConfig cataloging.LicenseConfig
}

// DefaultConfig returns a default configuration for external catalogers
func DefaultConfig() Config {
	return Config{
		ComplianceConfig:     cataloging.DefaultComplianceConfig(),
		SearchConfig:         cataloging.DefaultSearchConfig(),
		RelationshipsConfig:  cataloging.DefaultRelationshipsConfig(),
		DataGenerationConfig: cataloging.DefaultDataGenerationConfig(),
		LicenseConfig:        cataloging.DefaultLicenseConfig(),
	}
}

// RegisterCataloger registers an external cataloger that can receive configuration.
// The catalogerFactory function receives Config and returns a configured cataloger.
// Higher priority catalogers are processed first (default built-ins have priority 0).
//
// Example:
//   func newMyCataloger(cfg external.Config) pkg.Cataloger {
//       return &MyCataloger{licenseConfig: cfg.LicenseConfig}
//   }
//   err := external.RegisterCataloger("my-cataloger", newMyCataloger, 100, "custom", "binary")
func RegisterCataloger(name string, catalogerFactory func(Config) pkg.Cataloger, priority int, tags ...string) error {
	// Wrap the external factory function to convert config types
	internalFactory := func(internalCfg task.CatalogingFactoryConfig) pkg.Cataloger {
		externalCfg := Config{
			ComplianceConfig:     internalCfg.ComplianceConfig,
			SearchConfig:         internalCfg.SearchConfig,
			RelationshipsConfig:  internalCfg.RelationshipsConfig,
			DataGenerationConfig: internalCfg.DataGenerationConfig,
			LicenseConfig:        internalCfg.LicenseConfig,
		}
		return catalogerFactory(externalCfg)
	}

	return task.RegisterCataloger(name, internalFactory, priority, tags...)
}

// RegisterSimpleCataloger registers an external cataloger without configuration support.
// The catalogerFactory function takes no parameters and returns a cataloger.
// This is useful for simple catalogers that don't need configuration.
// Higher priority catalogers are processed first (default built-ins have priority 0).
//
// Example:
//   func newSimpleCataloger() pkg.Cataloger {
//       return &SimpleCataloger{}
//   }
//   err := external.RegisterSimpleCataloger("simple-cataloger", newSimpleCataloger, 100, "custom")
func RegisterSimpleCataloger(name string, catalogerFactory func() pkg.Cataloger, priority int, tags ...string) error {
	return task.RegisterSimpleCataloger(name, catalogerFactory, priority, tags...)
}

// ListRegisteredCatalogers returns the names of all registered external catalogers.
// This includes both simple and configurable catalogers but not built-in syft catalogers.
func ListRegisteredCatalogers() []string {
	return task.ListRegisteredCatalogers()
}

// HasRegisteredCataloger checks if a cataloger with the given name is registered.
// This only checks external catalogers, not built-in syft catalogers.
func HasRegisteredCataloger(name string) bool {
	return task.HasRegisteredCataloger(name)
}