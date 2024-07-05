package repodata

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/source"
)

type excludeFn func(string) bool
type repodataTestFileResolverMock struct {
	delegate  source.FileResolver
	excludeFn excludeFn
	isoPath   string
}

func newTestFileResolver(isoPath string) *repodataTestFileResolverMock {
	return &repodataTestFileResolverMock{
		isoPath: isoPath,
	}
}

func (r repodataTestFileResolverMock) HasPath(path string) bool {
	return true
}

func (r *repodataTestFileResolverMock) FilesByPath(paths ...string) ([]source.Location, error) {
	var locations = make([]source.Location, 1)
	locations[0] = source.NewLocation(r.isoPath)
	return locations, nil
}

func (r *repodataTestFileResolverMock) FilesByGlob(...string) ([]source.Location, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *repodataTestFileResolverMock) RelativeFileByPath(source.Location, string) *source.Location {
	panic(fmt.Errorf("not implemented"))
}

func (r *repodataTestFileResolverMock) FilesByMIMEType(...string) ([]source.Location, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *repodataTestFileResolverMock) Path() string {
	return ""
}

func (r *repodataTestFileResolverMock) FileContentsByLocation(_ source.Location) (io.ReadCloser, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *repodataTestFileResolverMock) FileMetadataByLocation(_ source.Location) (source.FileMetadata, error) {
	return source.FileMetadata{
		LinkDestination: "MOCK",
	}, nil
}

func (r *repodataTestFileResolverMock) AllLocations() <-chan source.Location {
	c := make(chan source.Location)
	go func() {
		defer close(c)
		for location := range r.delegate.AllLocations() {
			if !locationMatches(&location, r.excludeFn) {
				c <- location
			}
		}
	}()
	return c
}

func locationMatches(location *source.Location, exclusionFn excludeFn) bool {
	return exclusionFn(location.RealPath) || exclusionFn(location.VirtualPath)
}

func TestParseRepodata(t *testing.T) {
	isoFilePath := "D:\\SBOM\\openEuler\\22.03-LTS\\ISO\\openEuler-22.03-LTS-x86_64-dvd.iso"
	fileResolver := newTestFileResolver(isoFilePath)

	isoFileSystem, err := InitIsoFileSystem(fileResolver)
	if err != nil {
		t.Errorf("Failed to init iso file system: %+v", err)
	} else {
		t.Logf("Success resolve repodata file: %s", isoFilePath)
	}

	mdXmlFile, err := isoFileSystem.OpenFile(strings.Join([]string{ISO_REPODATA_FOLDER_NAME, REPODATA_MD_FILE_NAME}, ISO_PATH_SEPARATOR), os.O_RDONLY)
	if err != nil {
		t.Errorf("Failed to open md xml file: %+v", err)
	} else {
		t.Logf("Success open md xml file")
	}
	defer isoFileSystem.Close(mdXmlFile)

	repodataFileList, err := resolverRepodataFile(isoFileSystem, mdXmlFile)
	if err != nil {
		t.Errorf("Failed to resolver repodata file: %+v", err)
	} else {
		t.Logf("Success resolver repodata file: %s", isoFilePath)
	}
	defer repodataFileList.Close(isoFileSystem)

	allPkgs, _, err := parseRepodata(isoFileSystem, repodataFileList)
	if err != nil {
		t.Errorf("Failed to parse repodata file: %+v", err)
	} else {
		t.Logf("all packages info length: %d", len(allPkgs))
	}
}
