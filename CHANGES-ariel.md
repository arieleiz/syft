# CHANGES-ariel.md

This file tracks modifications made to the repository.

## 2025-01-31

### Public External Cataloger Registration API
- **syft/pkg/cataloger/external/register.go**: Created public API for external cataloger registration
  - Added `RegisterSimpleCataloger()` and `RegisterCataloger()` functions for external use
  - Added `Config` struct exposing safe subset of syft configuration to external catalogers  
  - Added `ListRegisteredCatalogers()` and `HasRegisteredCataloger()` utility functions
  - Wraps internal task registration APIs to avoid import cycles and maintain clean public interface
  - Provides access to compliance, search, relationships, data generation, and license configs

- **examples/register_exe_cataloger/main.go**: Updated to use public API
  - Changed import from `internal/task` to `syft/pkg/cataloger/external`
  - Updated function calls to use public registration interface
  - Maintains all existing functionality while being externally accessible

- **examples/register_configurable_cataloger/main.go**: New example demonstrating configurable catalogers
  - Shows how to create catalogers that receive and use syft configuration
  - Demonstrates license configuration usage in external catalogers
  - Example of more complex external cataloger factory patterns

### Benefits of Public API
- **External Accessibility**: External Go modules can now register catalogers without importing internal packages
- **Import Cycle Prevention**: Clean separation between public and internal APIs
- **Configuration Access**: External catalogers can access relevant syft configuration safely
- **Future Compatibility**: Public API can remain stable while internal implementation evolves
- **Documentation**: Clear public interface with examples for external developers

### External Distro Registration API
- **syft/linux/identify_release.go**: Implemented external distro registration API with Registry pattern
  - Added `Registry` struct with thread-safe parser registration
  - Added `RegisterParser()` function for external distro parsers with priority support
  - Converted static `identityFiles` slice to dynamic registry with built-in parsers
  - Maintained backward compatibility with existing `IdentifyRelease()` function
  - Added priority-based parser ordering (higher priority checked first)
  - Ensured busybox parser remains lowest priority (-1000)

- **examples/register_garden_linux/main.go**: Created comprehensive example showing:
  - How to register Garden Linux parser externally
  - Parsing custom Garden Linux fields (GARDENLINUX_VERSION, etc.)
  - Setting ID_LIKE=["debian"] for package cataloger compatibility
  - High priority registration to override built-in parsers

- **syft/linux/registry_test.go**: Added extensive test coverage:
  - Parser registration validation (nil checks, priority ordering)
  - Thread-safe registry operations (GetParsers defensive copying)
  - Built-in parser verification (all expected paths present)
  - Real Garden Linux fixture integration testing
  - External parser integration with actual test-fixtures/garden-linux
  - Package-level convenience function testing

### Architecture Benefits
- **Extensibility**: External packages can register new distro detection without modifying Syft core
- **Compatibility**: Existing DEB/RPM catalogers automatically work with new distros via ID_LIKE
- **Priority Control**: High-priority external parsers can override built-in detection
- **Thread Safety**: Concurrent registration and access safely handled
- **Backward Compatibility**: All existing code continues to work unchanged

### External Cataloger Registration API
- **internal/task/cataloger_registry.go**: Implemented external cataloger registration system
  - Added `CatalogerRegistry` struct with thread-safe cataloger registration
  - Added `RegisterCataloger()` and `RegisterSimpleCataloger()` functions
  - Priority-based ordering system (higher priority = processed first)
  - Full integration with existing task factory and selection system
  - Support for both config-aware and simple catalogers
  - Duplicate name protection and validation

- **internal/task/package_tasks.go**: Modified to include external catalogers
  - `DefaultPackageTaskFactories()` now combines built-in + external catalogers
  - External catalogers processed first when they have priority > 0
  - Maintains backward compatibility with existing built-in catalogers

- **examples/register_exe_cataloger/main.go**: Comprehensive .exe version cataloger example
  - Demonstrates PE file parsing for version extraction
  - Shows how to register custom catalogers with tags and priority
  - Example of creating packages with custom metadata types
  - Production-ready structure for Windows executable analysis

- **internal/task/cataloger_registry_test.go**: Extensive test coverage:
  - Registration validation (nil checks, duplicate names, priority ordering)
  - Thread-safe operations with defensive copying
  - Integration testing with task factory system
  - Both simple and complex cataloger factory patterns
  - Package-level convenience function testing

### External Cataloger System Benefits
- **Complete Extensibility**: Register any custom cataloger without modifying Syft core
- **Task System Integration**: External catalogers get parallel execution, configuration, tagging
- **Selection Support**: Use existing `--select` expressions with custom catalogers  
- **Priority Control**: High-priority external catalogers can run before built-ins
- **Thread Safety**: Concurrent registration and access safely handled
- **Zero Breaking Changes**: All existing catalogers and APIs continue to work
- **Production Ready**: Full validation, error handling, and testing

## 2025-01-31 (Earlier)
