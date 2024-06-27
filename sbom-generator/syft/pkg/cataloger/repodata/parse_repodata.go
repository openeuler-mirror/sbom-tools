package repodata

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/codingsince1985/checksum"
	_ "modernc.org/sqlite"
)

const mvnRegexpStr = `^mvn\(([A-Za-z0-9-_\.]*)\:([A-Za-z0-9-_\.]*)(\:([A-Za-z0-9-_\.]*))*\)`
const purlDefaultChecksumNamespace = "sha1"
const purlDefaultChecksumVersion = "1.0.0"
const packageIdPattern = "rpm-%s-%s"

func parsePackagesInfo(isoFileSystem IsoFileSystem, repodataFileList RepodataFileList, unzipDir string) ([]pkg.Package, error) {
	primaryDb, err := sql.Open("sqlite", repodataFileList.PrimarySqliteUnBzFilePath)
	if err != nil {
		return nil, err
	}
	defer primaryDb.Close()

	fileListDb, err := sql.Open("sqlite", repodataFileList.FilelistsSqliteUnBzFilePath)
	if err != nil {
		return nil, err
	}
	defer fileListDb.Close()

	sql := `SELECT
	pkgId,
	pkgKey,
	name,
	arch,
	version,
	epoch,
	RELEASE,
	ifnull( summary, "") summary,
	ifnull( description, "") description,
	rpm_sourcerpm sourceRpm,
	rpm_vendor vendor,
	ifnull( rpm_packager, "") packager,
	rpm_license license,
	size_installed size,
	ifnull( url, "") homepage,
	checksum_type checksumType,
	location_href locationHref
FROM
	packages`

	rows, err := primaryDb.Query(sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	allPkgs := make([]pkg.Package, 0)

	for rows.Next() {
		var pkgId string
		var pkgKey int
		var name string
		var arch string
		var version string
		var packager string
		var epoch string
		var release string
		var summary string
		var description string
		var sourceRpm string
		var vendor string
		var license string
		var size int
		var homepage string
		var checksumType string
		var locationHref string

		if err = rows.Scan(&pkgId, &pkgKey, &name, &arch, &version, &epoch, &release, &summary, &description, &sourceRpm, &vendor, &packager, &license, &size, &homepage, &checksumType, &locationHref); err != nil {
			log.Error(err)
			continue
		}
		epoch_int10, err := strconv.Atoi(epoch)
		if err != nil {
			log.Error(err)
			epoch_int10 = 0
		}

		rpmProvides, closeFn, err := queryMvnProvidesForPackage(*primaryDb, pkgKey, version)
		defer closeFn()
		if err != nil {
			log.Error(err)
		}

		javaFileList, err := queryJavaFileListForPackage(*fileListDb, pkgKey)
		if err != nil {
			log.Error(err)
		}

		javaPackages, err := covertJavaFileToPackage(javaFileList, isoFileSystem, unzipDir, locationHref)
		if err != nil {
			log.Error(err)
		}

		metadata := pkg.RpmRepodata{
			Name:        name,
			Version:     version,
			Epoch:       &epoch_int10,
			Arch:        arch,
			Release:     release,
			SourceRpm:   sourceRpm,
			Vendor:      vendor,
			Packager:    packager,
			License:     license,
			Size:        size,
			Homepage:    homepage,
			Summary:     summary,
			Description: description,
			RpmDigests: []file.Digest{{
				Algorithm: checksumType,
				Value:     pkgId,
			}},
			RpmProvides: rpmProvides,
			ExtPackage:  javaPackages,
			// Files:       extractRpmdbFileRecords(resolver, entry),
		}

		p := pkg.Package{
			Name:         name,
			Version:      toELVersion(metadata),
			Locations:    source.NewLocationSet(source.NewLocation(repodataFileList.PrimarySqliteBzFilePath)),
			Licenses:     []string{license},
			FoundBy:      catalogerName,
			Type:         pkg.RepodataPkg,
			MetadataType: pkg.RpmRepodataType,
			Metadata:     metadata,
		}

		// p.SetID()
		p.OverrideID(artifact.ID(fmt.Sprintf(packageIdPattern, name, version)))

		allPkgs = append(allPkgs, p)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return allPkgs, nil
}

func toELVersion(metadata pkg.RpmRepodata) string {
	if metadata.Epoch != nil {
		return fmt.Sprintf("%d:%s-%s", *metadata.Epoch, metadata.Version, metadata.Release)
	}
	return fmt.Sprintf("%s-%s", metadata.Version, metadata.Release)
}

func queryMvnProvidesForPackage(primaryDb sql.DB, pkgKey int, pkgVersion string) ([]pkg.RepodataPackageRecord, func(), error) {
	sql := `SELECT
		name,
		ifnull( version, "") version
	FROM
		provides
	WHERE
		pkgKey = ?
		AND name LIKE 'mvn(%'
		AND name NOT LIKE '%:pom:%'
		AND name NOT LIKE '%:xml:%'
		AND name NOT LIKE '%:sources:%'
		AND name NOT LIKE '%:sources-feature:%'`

	rows, err := primaryDb.Query(sql, pkgKey)
	defer primaryDb.Close()

	if err != nil {
		return []pkg.RepodataPackageRecord{}, func() {}, err
	}
	closeFn := func() {
		err := rows.Close()
		if err != nil {
			log.Errorf("unable to close primaryDb query rows, pkgKey: %s, %+v", pkgKey, err)
		}
	}

	mvnRegexp := regexp.MustCompile(mvnRegexpStr)
	rpmProvideMap := make(map[string]pkg.RepodataPackageRecord, 0)

	for rows.Next() {
		var name string
		var version string
		if err = rows.Scan(&name, &version); err != nil {
			log.Error(err)
			continue
		}

		if version == "" {
			version = pkgVersion
		}

		mvnCoordinate := mvnRegexp.FindStringSubmatch(name)
		groupId := mvnCoordinate[1]
		artifactId := mvnCoordinate[2]
		if len(mvnCoordinate) > 4 && mvnCoordinate[4] != "" {
			version = mvnCoordinate[4]
		}
		rpmProvide := pkg.RepodataPackageRecord{
			PkgType:    packageurl.TypeMaven,
			GroupId:    groupId,
			ArtifactId: artifactId,
			Version:    version,
		}

		rpmProvideMap[strings.Join([]string{rpmProvide.PkgType, rpmProvide.GroupId, rpmProvide.ArtifactId, rpmProvide.Version}, ":")] = rpmProvide
	}

	if err = rows.Err(); err != nil {
		return []pkg.RepodataPackageRecord{}, closeFn, err
	}

	rpmProvides := mapToSlice(rpmProvideMap)
	return rpmProvides, closeFn, nil
}

func queryJavaFileListForPackage(fileListDb sql.DB, pkgKey int) (map[string]string, error) {
	javaFileList := make(map[string]string, 0)

	sql := `SELECT
	dirname, filenames  
FROM
	filelist 
WHERE
	pkgKey = ? 
	AND filenames LIKE '%.jar%' 
	AND dirname NOT LIKE '/usr/share/java%'`
	rows, err := fileListDb.Query(sql, pkgKey)
	defer fileListDb.Close()

	if err != nil {
		return javaFileList, err
	}
	defer rows.Close()

	for rows.Next() {
		var dirname string
		var filenames string
		if err = rows.Scan(&dirname, &filenames); err != nil {
			log.Error(err)
			continue
		}

		filenameArr := strings.Split(filenames, "/")
		for _, filename := range filenameArr {
			if !strings.HasSuffix(filename, ".jar") {
				continue
			}
			javaFileList[filename] = strings.Join([]string{dirname, filename}, ISO_PATH_SEPARATOR)
		}
	}

	if err = rows.Err(); err != nil {
		return map[string]string{}, err
	}
	return javaFileList, nil
}

func covertJavaFileToPackage(javaFileList map[string]string, isoFileSystem IsoFileSystem, unzipDir string, locationHref string) ([]pkg.RepodataPackageRecord, error) {
	javaPackages := make([]pkg.RepodataPackageRecord, 0)
	if len(javaFileList) == 0 {
		return javaPackages, nil
	}

	rpmUnzipDirPath, cleanupRpmTempDirFn, err := extractRpmToTempDir(isoFileSystem, unzipDir, locationHref)
	defer cleanupRpmTempDirFn()
	if err != nil {
		return javaPackages, err
	}

	javaPackagesMap := make(map[string]pkg.RepodataPackageRecord, 0)
	for _, jarPath := range javaFileList {
		jarAbsolutePath := filepath.Join(rpmUnzipDirPath, jarPath)
		if !fileExists(jarAbsolutePath) {
			log.Debugf("file:%s is not exists, not calculate checksum", jarAbsolutePath)
			continue
		}
		sha1, err := checksum.SHA1sum(jarAbsolutePath)
		if err != nil {
			log.Error(err)
			continue
		}

		// restResult, err := resty.New().R().SetQueryParams(map[string]string{
		// 	"q":    "1:" + sha1,
		// 	"rows": "1",
		// 	"wt":   "json",
		// }).SetHeader("Accept", "application/json").
		// 	Get("https://search.maven.org/solrsearch/select")
		// if err != nil {
		// 	log.Error(err)
		// 	continue
		// }
		// mvnResult, err := jsonquery.Parse(bytes.NewReader(restResult.Body()))
		// if err != nil {
		// 	log.Errorf("%s`s result body: %s, error info: %v", jarPath, restResult.Body(), err)
		// 	continue
		// }
		// if numFound := jsonquery.FindOne(mvnResult, "response/numFound"); numFound == nil || numFound.InnerText() == "0" {
		// 	log.Warnf("%s `s jar:%s, can not find artifact in maven central. sha1: %s", locationHref, jarPath, sha1)
		// 	continue
		// }

		// groupId := jsonquery.FindOne(mvnResult, "response/docs/*/g").InnerText()
		// artifactId := jsonquery.FindOne(mvnResult, "response/docs/*/a").InnerText()
		// version := jsonquery.FindOne(mvnResult, "response/docs/*/v").InnerText()

		// TODO use config param to switch between GAV or checksum

		jarPackage := pkg.RepodataPackageRecord{
			PkgType:    packageurl.TypeMaven,
			GroupId:    purlDefaultChecksumNamespace,
			ArtifactId: sha1,
			Version:    purlDefaultChecksumVersion,
		}
		javaPackagesMap[strings.Join([]string{jarPackage.PkgType, jarPackage.GroupId, jarPackage.ArtifactId, jarPackage.Version}, ":")] = jarPackage
	}
	javaPackages = mapToSlice(javaPackagesMap)
	return javaPackages, nil
}

func extractRpmToTempDir(isoFileSystem IsoFileSystem, unzipDir string, rpmPath string) (string, func(), error) {
	rpmFileName := filepath.Base(rpmPath)
	rpmName := strings.TrimSuffix(rpmFileName, ".rpm")
	rpmUnzipDirPath := filepath.Join(unzipDir, rpmName)
	// 需要在外部加载完jar包后再移除目录
	cleanupFn := func() {
		err := os.RemoveAll(rpmUnzipDirPath)
		if err != nil {
			log.Errorf("unable to cleanup repodata temp dir: %+v", err)
		}
	}

	if createErr := createDirIfNotExist(rpmUnzipDirPath); createErr != nil {
		log.Errorf("failed to create repodata dir: %+v", createErr)
		return "", cleanupFn, createErr
	}

	rpmFile, err := isoFileSystem.OpenFile(rpmPath, os.O_RDONLY)
	if err != nil {
		return "", cleanupFn, err
	}
	defer isoFileSystem.Close(rpmFile)

	err = ExtractRPM(rpmFile, rpmUnzipDirPath)
	if err != nil {
		return "", cleanupFn, err
	}

	return rpmUnzipDirPath, cleanupFn, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		return os.IsExist(err)
	}
	return true
}

func mapToSlice(input map[string]pkg.RepodataPackageRecord) []pkg.RepodataPackageRecord {
	output := make([]pkg.RepodataPackageRecord, 0)
	for _, v := range input {
		output = append(output, v)
	}
	return output
}

func parseRelationship(repodataFileList RepodataFileList) ([]artifact.Relationship, error) {
	primaryDb, err := sql.Open("sqlite", repodataFileList.PrimarySqliteUnBzFilePath)
	if err != nil {
		return nil, err
	}
	defer primaryDb.Close()

	sql := `SELECT DISTINCT
					fromPkg.name fromPkgName,
					fromPkg.version fromPkgVersion,
					toPkg.name toPkgName,
					toPkg.version toPkgVersion
				FROM
					requires r,
					provides pro
					LEFT JOIN packages AS fromPkg ON fromPkg.pkgKey = r.pkgKey 
					LEFT JOIN packages AS toPkg ON toPkg.pkgKey = pro.pkgKey 
				WHERE
					r.name = pro.name 
				ORDER BY
					r.pkgKey,
					pro.pkgKey`

	rows, err := primaryDb.Query(sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	allRelationships := make([]artifact.Relationship, 0)

	for rows.Next() {
		var fromPkgName string
		var fromPkgVersion string
		var toPkgName string
		var toPkgVersion string

		if err = rows.Scan(&fromPkgName, &fromPkgVersion, &toPkgName, &toPkgVersion); err != nil {
			log.Error(err)
			continue
		}

		fromPkg := pkg.Package{}
		fromPkg.OverrideID(artifact.ID(fmt.Sprintf(packageIdPattern, fromPkgName, fromPkgVersion)))

		toPkg := pkg.Package{}
		toPkg.OverrideID(artifact.ID(fmt.Sprintf(packageIdPattern, toPkgName, toPkgVersion)))

		r := artifact.Relationship{
			From: fromPkg,
			To:   toPkg,
			Type: artifact.DependsOnRelationship,
		}

		allRelationships = append(allRelationships, r)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return allRelationships, nil
}
