package repodata

import (
	"fmt"
	"os"
	"strings"

	"github.com/anchore/syft/internal/log"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const catalogerName = "repodata-cataloger"

// FIXME 此处路径分隔符，在windows场景下，无法适配ISO内部路径
const ISO_PATH_SEPARATOR = "/"
const ISO_REPODATA_FOLDER_NAME = "repodata"

const REPODATA_ISO_SUFFIX = "iso"
const SQLITE_FILE_NAME_SUFFIX = "-primary.sqlite.bz2"
const REPODATA_MD_FILE_NAME = "repomd.xml"

type Cataloger struct{}

func NewRepodataCataloger() *Cataloger {
	return &Cataloger{}
}

func (c *Cataloger) Name() string {
	return catalogerName
}

func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	isoFileSystem, err := InitIsoFileSystem(resolver)
	if err != nil {
		return nil, nil, err
	}

	mdXmlFile, err := isoFileSystem.OpenFile(strings.Join([]string{ISO_REPODATA_FOLDER_NAME, REPODATA_MD_FILE_NAME}, ISO_PATH_SEPARATOR), os.O_RDONLY)
	if err != nil {
		log.Debugf("can`t find iso`s repomd.xml, %+v", err)
		return []pkg.Package{}, nil, nil
	}
	defer isoFileSystem.Close(mdXmlFile)

	repodataFileList, err := resolverRepodataFile(isoFileSystem, mdXmlFile)
	if err != nil {
		log.Errorf("resolver repodata file failed, %+v", err)
		return []pkg.Package{}, nil, nil
	}
	defer repodataFileList.Close(isoFileSystem)

	return parseRepodata(isoFileSystem, repodataFileList)
}

func parseRepodata(isoFileSystem IsoFileSystem, repodataFileList RepodataFileList) ([]pkg.Package, []artifact.Relationship, error) {
	repodataTempDir, cleanupFn, err := createRepodataTempDir()
	defer cleanupFn()
	if err != nil {
		return nil, nil, err
	}

	repodataFileList, err = unBzip2ForRepodata(repodataFileList, repodataTempDir)
	if err != nil {
		return nil, nil, err
	}

	discoveredPkgs, err := parsePackagesInfo(isoFileSystem, repodataFileList, repodataTempDir)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse repodata for package: %w", err)
	}

	discoveredShips, err := parseRelationship(repodataFileList)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse repodata for relationship: %w", err)
	}

	return discoveredPkgs, discoveredShips, nil
}
