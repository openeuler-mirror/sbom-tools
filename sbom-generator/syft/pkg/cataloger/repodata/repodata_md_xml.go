package repodata

import (
	"encoding/xml"
	"io"
	"io/ioutil"
)

type Repomd struct {
	XMLName  xml.Name `xml:"repomd"`
	Revision int      `xml:"revision"`
	Datas    []Data   `xml:"data"`
}

type Data struct {
	XMLName      xml.Name  `xml:"data"`
	Type         string    `xml:"type,attr"`
	Location     SLocation `xml:"location"`
	Checksum     string    `xml:"checksum"`
	OpenChecksum string    `xml:"open-checksum"`
	Timestamp    int       `xml:"timestamp"`
	Size         int       `xml:"size"`
	OpenSize     int       `xml:"open-size"`
}

type SLocation struct {
	XMLName xml.Name `xml:"location"`
	Path    string   `xml:"href,attr"`
}

func readRepoMdXML(reader io.Reader) (RepodataFileList, error) {
	repodataFileList := RepodataFileList{}

	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return repodataFileList, err
	}

	repomd := Repomd{}
	err = xml.Unmarshal(data, &repomd)
	if err != nil {
		return repodataFileList, err
	}

	for _, data := range repomd.Datas {
		if data.Type == "primary_db" {
			repodataFileList.PrimarySqliteBzFilePath = data.Location.Path
		} else if data.Type == "filelists_db" {
			repodataFileList.FilelistsSqliteBzFilePath = data.Location.Path
		} else if data.Type == "other_db" {
			repodataFileList.OtherSqliteBzFilePath = data.Location.Path
		}
	}

	return repodataFileList, nil
}
