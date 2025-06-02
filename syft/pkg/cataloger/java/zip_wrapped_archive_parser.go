package java

import (
	"context"
	"fmt"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var genericZipGlobs = []string{
	"**/*.zip",
}

// TODO: when the generic archive cataloger is implemented, this should be removed (https://github.com/anchore/syft/issues/246)

// parseZipWrappedJavaArchive is a parser function for java archive contents contained within arbitrary zip files.

type genericZipWrappedJavaArchiveParser struct {
	cfg ArchiveCatalogerConfig
}

func newGenericZipWrappedJavaArchiveParser(cfg ArchiveCatalogerConfig) genericZipWrappedJavaArchiveParser {
	return genericZipWrappedJavaArchiveParser{
		cfg: cfg,
	}
}

func (gzp genericZipWrappedJavaArchiveParser) parseZipWrappedJavaArchive(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	// Use memory-based approach instead of saving to temp
	archiveReader, err := intFile.CreateArchiveReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create archive reader: %w", err)
	}
	defer archiveReader.Close()

	// look for java archives within the zip archive using memory-based access
	return gzp.discoverPkgsFromMemoryZip(ctx, reader.Location, archiveReader)
}

// discoverPkgsFromMemoryZip finds Java archives within ZIP using memory-based access
func (gzp genericZipWrappedJavaArchiveParser) discoverPkgsFromMemoryZip(ctx context.Context, location file.Location, archiveReader intFile.ArchiveReader) ([]pkg.Package, []artifact.Relationship, error) {
	manifest := archiveReader.GetManifest()
	nestedArchivePaths := manifest.GlobMatch(false, archiveFormatGlobs...)
	
	if len(nestedArchivePaths) == 0 {
		return nil, nil, nil
	}

	openers := make(map[string]intFile.Opener)
	for _, path := range nestedArchivePaths {
		reader, err := archiveReader.OpenFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to open nested archive %s: %w", path, err)
		}
		openers[path] = intFile.MemoryOpener{ReadCloser: reader}
	}

	return discoverPkgsFromOpeners(ctx, location, openers, nil, gzp.cfg)
}
