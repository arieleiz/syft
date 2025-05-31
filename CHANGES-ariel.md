# CHANGES-ariel.md

This file tracks modifications made to the repository.

## 2025-01-31

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

## 2025-01-31 (Earlier)
