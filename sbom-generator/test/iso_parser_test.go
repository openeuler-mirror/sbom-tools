package test

import (
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/kdomanski/iso9660"
)

func TestMain(t *testing.T) {
	ExtractRepodataToDirectory("D:\\SBOM\\openEuler\\22.03-LTS\\ISO\\openEuler-22.03-LTS-x86_64-dvd.iso", "D:\\SBOM\\openEuler\\22.03-LTS\\ISO\\iso")
}

func ExtractRepodataToDirectory(isoFilePath string, destination string) {
	if createErr := createDirIfNotExist(destination); createErr != nil {
		log.Fatalf("failed to create destination dir: %+v", createErr)
		return
	}

	f, err := os.Open(isoFilePath)
	if err != nil {
		log.Fatalf("failed to open file: %+v", err)
	}
	defer f.Close()

	if err = ExtractImageToDirectory(f, destination); err != nil {
		log.Fatalf("failed to extract image: %+v", err)
	}
}

func ExtractImageToDirectory(image io.ReaderAt, destination string) error {
	img, err := iso9660.OpenImage(image)
	if err != nil {
		return err
	}

	root, err := img.RootDir()
	if err != nil {
		return err
	}

	return extract(root, "", destination)
}

func extract(f *iso9660.File, filePath string, targetPath string) error {
	if f.IsDir() {
		if strings.EqualFold("repodata", f.Name()) {
			filePath := path.Join(filePath, f.Name())
			if createErr := createDirIfNotExist(targetPath + string(os.PathSeparator) + filePath); createErr != nil {
				return createErr
			}
		} else if f.Name() == "\x00" {
		} else {
			return nil
		}

		fmt.Println("dir name:" + filePath)

		children, err := f.GetChildren()
		if err != nil {
			return err
		}

		for _, c := range children {
			if err = extract(c, filePath, targetPath); err != nil {
				return err
			}
		}
	} else {
		filePath = path.Join(filePath, f.Name())

		fmt.Println("file name:" + filePath)

		targetPath = targetPath + string(os.PathSeparator) + filePath
		newFile, err := os.Create(targetPath)
		if err != nil {
			return err
		}
		defer newFile.Close()
		if _, err = io.Copy(newFile, f.Reader()); err != nil {
			return err
		}
	}

	return nil
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
