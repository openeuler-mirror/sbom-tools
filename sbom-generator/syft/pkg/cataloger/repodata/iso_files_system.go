package repodata

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/source"
	"github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/filesystem"
)

// 针对ISO的两种格式：镜像文件和文件夹，抽象为统一的结构体，方便后续逻辑统一操作
type IsoFileSystem struct {
	isIsoFile bool
	isIsoDir  bool
	fs        filesystem.FileSystem
	resolver  source.FileResolver
}

func InitIsoFileSystem(resolver source.FileResolver) (IsoFileSystem, error) {
	emptyIsoFileSystem := IsoFileSystem{}

	// init for input of iso file
	if isIsoFileInput(resolver) {
		rootFiles, _ := resolver.FilesByPath("")
		inputLocation := rootFiles[0]
		log.Infof("resolver repodata from input iso: %q", inputLocation.RealPath)

		// mount iso to filesystem
		disk, err := diskfs.OpenWithMode(inputLocation.RealPath, diskfs.ReadOnly)
		if err != nil {
			log.Error(err)
			return emptyIsoFileSystem, err
		}

		fs, err := disk.GetFilesystem(0)
		if err != nil {
			log.Error(err)
			return emptyIsoFileSystem, err
		}

		isoFileSystem := IsoFileSystem{
			isIsoFile: true,
			isIsoDir:  false,
			fs:        fs,
			resolver:  resolver,
		}

		return isoFileSystem, nil
	}

	// init for input of iso dir
	return IsoFileSystem{
		isIsoFile: false,
		isIsoDir:  true,
		fs:        nil,
		resolver:  resolver,
	}, nil
}

func isIsoFileInput(resolver source.FileResolver) bool {
	rootFiles, err := resolver.FilesByPath("")
	if len(rootFiles) == 1 && err == nil {
		inputLocation := rootFiles[0]
		if !isLocationDir(inputLocation) && strings.HasSuffix(inputLocation.RealPath, REPODATA_ISO_SUFFIX) {
			return true
		}
	}
	return false
}

func (isoFS IsoFileSystem) OpenFile(filePath string, openMode int) (io.Reader, error) {
	if isoFS.isIsoFile {
		filePath = strings.Join([]string{"", filePath}, ISO_PATH_SEPARATOR)
		return isoFS.fs.OpenFile(filePath, openMode)
	} else if isoFS.isIsoDir {
		filePath = strings.Join([]string{isoFS.resolver.Path(), filePath}, ISO_PATH_SEPARATOR)
		return os.OpenFile(filePath, openMode, 0)
	}
	return nil, fmt.Errorf("the IOS type is neither file nor dir")
}

type Closer interface {
	Close() error
}

func (isoFS IsoFileSystem) Close(file io.Reader) error {
	if i, ok := file.(Closer); ok {
		return i.Close()
	}
	return nil
}
