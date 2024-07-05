package repodata

import (
	"fmt"
	"io"
)

type RepodataFileList struct {
	PrimarySqliteBzFilePath     string
	PrimarySqliteBzFile         io.Reader
	PrimarySqliteUnBzFilePath   string
	FilelistsSqliteBzFilePath   string
	FilelistsSqliteBzFile       io.Reader
	FilelistsSqliteUnBzFilePath string
	OtherSqliteBzFilePath       string
	OtherSqliteBzFile           io.Reader
	OtherSqliteUnBzFilePath     string
}

func (fileList RepodataFileList) IsFindAllFilesPath() error {
	if fileList.PrimarySqliteBzFilePath == "" {
		return fmt.Errorf("primary sqlite file of not found")
	}

	if fileList.FilelistsSqliteBzFilePath == "" {
		return fmt.Errorf("filelists sqlite file of not found")
	}

	if fileList.OtherSqliteBzFilePath == "" {
		return fmt.Errorf("other sqlite file of not found")
	}

	return nil
}

func (fileList RepodataFileList) Close(isoFS IsoFileSystem) bool {
	if fileList.PrimarySqliteBzFile != nil {
		isoFS.Close(fileList.PrimarySqliteBzFile)
	}

	if fileList.FilelistsSqliteBzFile != nil {
		isoFS.Close(fileList.FilelistsSqliteBzFile)
	}

	if fileList.OtherSqliteBzFile != nil {
		isoFS.Close(fileList.OtherSqliteBzFile)
	}

	return true
}
