package repodata

import (
	"compress/bzip2"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/source"
	"github.com/xi2/xz"

	"github.com/cavaliergopher/cpio"
	"github.com/cavaliergopher/rpm"
)

func resolverRepodataFile(isoFS IsoFileSystem, xmlReader io.Reader) (RepodataFileList, error) {
	repodataFileList, err := readRepoMdXML(xmlReader)
	if err != nil {
		return RepodataFileList{}, err
	} else if err := repodataFileList.IsFindAllFilesPath(); err != nil { // 需要三个文件地址同时都获取到
		return RepodataFileList{}, err
	}

	primarySqliteBzFile, err := isoFS.OpenFile(repodataFileList.PrimarySqliteBzFilePath, os.O_RDONLY)
	if err != nil {
		return RepodataFileList{}, err
	}
	repodataFileList.PrimarySqliteBzFile = primarySqliteBzFile

	filelistsSqliteBzFile, err := isoFS.OpenFile(repodataFileList.FilelistsSqliteBzFilePath, os.O_RDONLY)
	if err != nil {
		return RepodataFileList{}, err
	}
	repodataFileList.FilelistsSqliteBzFile = filelistsSqliteBzFile

	otherSqliteBzFile, err := isoFS.OpenFile(repodataFileList.OtherSqliteBzFilePath, os.O_RDONLY)
	if err != nil {
		return RepodataFileList{}, err
	}
	repodataFileList.OtherSqliteBzFile = otherSqliteBzFile

	return repodataFileList, err
}

func isLocationDir(location source.Location) bool {
	fileMeta, err := os.Stat(location.RealPath)
	if err != nil {
		log.Warnf("path is not valid (%s): %+v", location.RealPath, err)
		return false
	}
	return fileMeta.IsDir()
}

func createRepodataTempDir() (string, func(), error) {
	// create temp dir for sqlite file
	tempDir, err := ioutil.TempDir("", internal.ApplicationName+"-repodata")
	if err != nil {
		log.Errorf("failed to create temp dir: %+v", err)
		return "", func() {}, err
	}

	cleanupFn := func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			log.Errorf("unable to cleanup repodata temp dir: %+v", err)
		}
	}

	repodataTempPath := filepath.Join(tempDir, ISO_REPODATA_FOLDER_NAME)
	if createErr := createDirIfNotExist(repodataTempPath); createErr != nil {
		log.Errorf("failed to create repodata dir: %+v", err)
		return "", cleanupFn, err
	}

	// FIXME: remove Println
	fmt.Printf("repodata temp dir: %s \n", repodataTempPath)
	log.Infof("repodata temp dir: %s", repodataTempPath)
	return repodataTempPath, cleanupFn, nil
}

func unBzip2ForRepodata(repodataFileList RepodataFileList, unzipDir string) (RepodataFileList, error) {
	primarySqliteUnBzFilePath, err := unBzip2SqliteFile(repodataFileList.PrimarySqliteBzFilePath, repodataFileList.PrimarySqliteBzFile, unzipDir)
	if err != nil {
		return repodataFileList, err
	}
	repodataFileList.PrimarySqliteUnBzFilePath = primarySqliteUnBzFilePath

	filelistsSqliteUnBzFilePath, err := unBzip2SqliteFile(repodataFileList.FilelistsSqliteBzFilePath, repodataFileList.FilelistsSqliteBzFile, unzipDir)
	if err != nil {
		return repodataFileList, err
	}
	repodataFileList.FilelistsSqliteUnBzFilePath = filelistsSqliteUnBzFilePath

	otherSqliteUnBzFilePath, err := unBzip2SqliteFile(repodataFileList.OtherSqliteBzFilePath, repodataFileList.OtherSqliteBzFile, unzipDir)
	if err != nil {
		return repodataFileList, err
	}
	repodataFileList.OtherSqliteUnBzFilePath = otherSqliteUnBzFilePath

	return repodataFileList, nil
}

func unBzip2SqliteFile(bzip2FilePath string, bzip2File io.Reader, unzipDir string) (string, error) {
	bzip2FileName := filepath.Base(bzip2FilePath)
	unBzip2FileName := strings.TrimSuffix(bzip2FileName, ".bz2")
	unBzip2FilePath := filepath.Join(unzipDir, unBzip2FileName)
	dstWriter, err := os.Create(unBzip2FilePath)
	if err != nil {
		return unBzip2FilePath, err
	}
	defer dstWriter.Close()

	sourceReader := bzip2.NewReader(bzip2File)

	if err := file.SafeCopy(dstWriter, sourceReader); err != nil {
		return unBzip2FilePath, fmt.Errorf("unable to copy source=%q for tar=%q: %w", bzip2File, unBzip2FilePath, err)
	}

	return unBzip2FilePath, nil
}

func createDirIfNotExist(targetPath string) error {
	existing, err := os.Open(targetPath)
	if err == nil {
		defer existing.Close()
		s, err := existing.Stat()
		if err != nil {
			return err
		}

		if !s.IsDir() {
			return fmt.Errorf("%s already exists and is a file", targetPath)
		}
	} else if os.IsNotExist(err) {
		if err = os.Mkdir(targetPath, 0755); err != nil {
			return err
		}
	}
	return err
}

func ExtractRPM(rpmFile io.Reader, targetDir string) error {
	pkg, err := rpm.Read(rpmFile)
	if err != nil {
		return err
	}

	xzReader, err := xz.NewReader(rpmFile, 0)
	if err != nil {
		return err
	}

	if format := pkg.PayloadFormat(); format != "cpio" {
		return fmt.Errorf("unsupported payload format: %s", format)
	}

	cpioReader := cpio.NewReader(xzReader)
	for {
		hdr, err := cpioReader.Next()
		if err == io.EOF {
			break // no more files
		}
		if err != nil {
			return err
		}

		// Skip directories and other irregular file types in this example
		if !hdr.Mode.IsRegular() {
			continue
		}
		if !strings.HasSuffix(hdr.Name, ".jar") {
			continue
		}

		if dirName := filepath.Dir(hdr.Name); dirName != "" {
			if err := os.MkdirAll(filepath.Join(targetDir, dirName), 0o755); err != nil {
				return err
			}
		}

		outFile, err := os.Create(filepath.Join(targetDir, hdr.Name))
		if err != nil {
			return err
		}
		if _, err := io.Copy(outFile, cpioReader); err != nil {
			outFile.Close()
			return err
		}
		outFile.Close()
	}
	return nil
}
