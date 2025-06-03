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

var genericTarGlobs = []string{
	"**/*.tar",
	// gzipped tar
	"**/*.tar.gz",
	"**/*.tgz",
	// bzip2
	"**/*.tar.bz",
	"**/*.tar.bz2",
	"**/*.tbz",
	"**/*.tbz2",
	// brotli
	"**/*.tar.br",
	"**/*.tbr",
	// lz4
	"**/*.tar.lz4",
	"**/*.tlz4",
	// sz
	"**/*.tar.sz",
	"**/*.tsz",
	// xz
	"**/*.tar.xz",
	"**/*.txz",
	// zst
	"**/*.tar.zst",
	"**/*.tzst",
	"**/*.tar.zstd",
	"**/*.tzstd",
}

// TODO: when the generic archive cataloger is implemented, this should be removed (https://github.com/anchore/syft/issues/246)

// parseTarWrappedJavaArchive is a parser function for java archive contents contained within arbitrary tar files.
// note: for compressed tars this is an extremely expensive operation and can lead to performance degradation. This is
// due to the fact that there is no central directory header (say as in zip), which means that in order to get
// a file listing within the archive you must decompress the entire archive and seek through all of the entries.

type genericTarWrappedJavaArchiveParser struct {
	cfg ArchiveCatalogerConfig
}

func newGenericTarWrappedJavaArchiveParser(cfg ArchiveCatalogerConfig) genericTarWrappedJavaArchiveParser {
	return genericTarWrappedJavaArchiveParser{
		cfg: cfg,
	}
}

func (gtp genericTarWrappedJavaArchiveParser) parseTarWrappedJavaArchive(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	// Use memory-based approach instead of saving to temp
	archiveReader, err := intFile.CreateArchiveReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create archive reader: %w", err)
	}
	defer archiveReader.Close()

	// look for java archives within the tar archive using memory-based access
	return gtp.discoverPkgsFromMemoryTar(ctx, reader.Location, archiveReader)
}

// discoverPkgsFromMemoryTar finds Java archives within TAR using memory-based access
func (gtp genericTarWrappedJavaArchiveParser) discoverPkgsFromMemoryTar(ctx context.Context, location file.Location, archiveReader intFile.ArchiveReader) ([]pkg.Package, []artifact.Relationship, error) {
	manifest := archiveReader.GetManifest()
	nestedArchivePaths := manifest.GlobMatch(false, archiveFormatGlobs...)

	if len(nestedArchivePaths) == 0 {
		return nil, nil, nil
	}

	openers := make(map[string]intFile.OpenerInterface)
	for _, path := range nestedArchivePaths {
		reader, err := archiveReader.OpenFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to open nested archive %s: %w", path, err)
		}
		openers[path] = intFile.MemoryOpener{ReadCloser: reader}
	}

	return discoverPkgsFromOpeners(ctx, location, openers, nil, gtp.cfg)
}

func discoverPkgsFromTar(ctx context.Context, location file.Location, archivePath, contentPath string, cfg ArchiveCatalogerConfig) ([]pkg.Package, []artifact.Relationship, error) {
	openers, err := intFile.ExtractGlobsFromTarToUniqueTempFile(archivePath, contentPath, archiveFormatGlobs...)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to extract files from tar: %w", err)
	}

	return discoverPkgsFromOpeners(ctx, location, openers, nil, cfg)
}
