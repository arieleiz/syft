package file

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZipArchiveReader(t *testing.T) {
	// Create a test ZIP archive in memory
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	// Add test files
	files := map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nMain-Class: com.example.Main\n",
		"pom.properties":       "groupId=com.example\nartifactId=test\nversion=1.0\n",
		"nested.jar":           "fake jar content",
	}

	for name, content := range files {
		writer, err := zipWriter.Create(name)
		require.NoError(t, err)
		_, err = writer.Write([]byte(content))
		require.NoError(t, err)
	}

	err := zipWriter.Close()
	require.NoError(t, err)

	// Create reader from buffer
	reader := bytes.NewReader(buf.Bytes())
	archiveReader, err := NewZipArchiveReader(reader, int64(buf.Len()), io.NopCloser(reader))
	require.NoError(t, err)
	defer archiveReader.Close()

	t.Run("GetManifest", func(t *testing.T) {
		manifest := archiveReader.GetManifest()
		allFiles := manifest.AllFiles()
		assert.Len(t, allFiles, 3)
		assert.Contains(t, allFiles, "META-INF/MANIFEST.MF")
		assert.Contains(t, allFiles, "pom.properties")
		assert.Contains(t, allFiles, "nested.jar")
	})

	t.Run("GlobMatch", func(t *testing.T) {
		manifest := archiveReader.GetManifest()
		manifestFiles := manifest.GlobMatch(false, "**/MANIFEST.MF")
		assert.Len(t, manifestFiles, 1)
		assert.Equal(t, "META-INF/MANIFEST.MF", manifestFiles[0])

		jarFiles := manifest.GlobMatch(false, "*.jar")
		assert.Len(t, jarFiles, 1)
		assert.Equal(t, "nested.jar", jarFiles[0])
	})

	t.Run("GetFileContent", func(t *testing.T) {
		content, err := archiveReader.GetFileContent("pom.properties")
		require.NoError(t, err)
		assert.Equal(t, files["pom.properties"], content)
	})

	t.Run("OpenFile", func(t *testing.T) {
		reader, err := archiveReader.OpenFile("META-INF/MANIFEST.MF")
		require.NoError(t, err)
		defer reader.Close()

		content, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, files["META-INF/MANIFEST.MF"], string(content))
	})
}

func TestTarArchiveReader(t *testing.T) {
	// Create a test TAR archive in memory
	var buf bytes.Buffer
	tarWriter := tar.NewWriter(&buf)

	// Add test files
	files := map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nMain-Class: com.example.Main\n",
		"pom.properties":       "groupId=com.example\nartifactId=test\nversion=1.0\n",
		"nested.jar":           "fake jar content",
	}

	for name, content := range files {
		header := &tar.Header{
			Name:     name,
			Size:     int64(len(content)),
			Mode:     0644,
			Typeflag: tar.TypeReg,
		}
		err := tarWriter.WriteHeader(header)
		require.NoError(t, err)
		_, err = tarWriter.Write([]byte(content))
		require.NoError(t, err)
	}

	err := tarWriter.Close()
	require.NoError(t, err)

	// Create reader from buffer
	reader := bytes.NewReader(buf.Bytes())
	archiveReader, err := NewTarArchiveReader(reader, io.NopCloser(reader))
	require.NoError(t, err)
	defer archiveReader.Close()

	t.Run("GetManifest", func(t *testing.T) {
		manifest := archiveReader.GetManifest()
		allFiles := manifest.AllFiles()
		assert.Len(t, allFiles, 3)
		assert.Contains(t, allFiles, "META-INF/MANIFEST.MF")
		assert.Contains(t, allFiles, "pom.properties")
		assert.Contains(t, allFiles, "nested.jar")
	})

	t.Run("GlobMatch", func(t *testing.T) {
		manifest := archiveReader.GetManifest()
		manifestFiles := manifest.GlobMatch(false, "**/MANIFEST.MF")
		assert.Len(t, manifestFiles, 1)
		assert.Equal(t, "META-INF/MANIFEST.MF", manifestFiles[0])

		jarFiles := manifest.GlobMatch(false, "*.jar")
		assert.Len(t, jarFiles, 1)
		assert.Equal(t, "nested.jar", jarFiles[0])
	})

	t.Run("GetFileContent", func(t *testing.T) {
		content, err := archiveReader.GetFileContent("pom.properties")
		require.NoError(t, err)
		assert.Equal(t, files["pom.properties"], content)
	})

	t.Run("OpenFile", func(t *testing.T) {
		reader, err := archiveReader.OpenFile("META-INF/MANIFEST.MF")
		require.NoError(t, err)
		defer reader.Close()

		content, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, files["META-INF/MANIFEST.MF"], string(content))
	})
}

func TestMemoryOpener(t *testing.T) {
	content := "test content"
	readCloser := io.NopCloser(strings.NewReader(content))
	opener := MemoryOpener{ReadCloser: readCloser}

	reader, err := opener.Open()
	require.NoError(t, err)
	defer reader.Close()

	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, content, string(data))
}

func TestArchiveReaderFactory(t *testing.T) {
	t.Run("DetectZIP", func(t *testing.T) {
		zipMagic := []byte{0x50, 0x4b, 0x03, 0x04, 0x00, 0x00}
		assert.True(t, isZipArchive(zipMagic))

		notZip := []byte{0x00, 0x01, 0x02, 0x03}
		assert.False(t, isZipArchive(notZip))
	})

	t.Run("DetectTAR", func(t *testing.T) {
		// Create TAR magic at offset 257
		tarMagic := make([]byte, 512)
		copy(tarMagic[257:262], []byte("ustar"))
		assert.True(t, isTarArchive(tarMagic))

		notTar := make([]byte, 512)
		assert.False(t, isTarArchive(notTar))
	})
}

// TestNoTempFiles verifies that no temporary files are created during archive processing
func TestNoTempFiles(t *testing.T) {
	// Monitor /tmp before and after to ensure no files are created
	tempDir := os.TempDir()
	
	// Get initial file count
	initialFiles, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	initialCount := len(initialFiles)

	// Create and process a test ZIP archive
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)
	
	writer, err := zipWriter.Create("test.txt")
	require.NoError(t, err)
	_, err = writer.Write([]byte("test content"))
	require.NoError(t, err)
	
	err = zipWriter.Close()
	require.NoError(t, err)

	// Process with memory-based reader
	reader := bytes.NewReader(buf.Bytes())
	archiveReader, err := NewZipArchiveReader(reader, int64(buf.Len()), io.NopCloser(reader))
	require.NoError(t, err)
	
	// Read file content
	content, err := archiveReader.GetFileContent("test.txt")
	require.NoError(t, err)
	assert.Equal(t, "test content", content)
	
	err = archiveReader.Close()
	require.NoError(t, err)

	// Verify no new files in temp directory
	finalFiles, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	finalCount := len(finalFiles)
	
	assert.Equal(t, initialCount, finalCount, "No temporary files should be created")
}