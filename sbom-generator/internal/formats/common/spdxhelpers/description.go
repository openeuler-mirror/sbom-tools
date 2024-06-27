package spdxhelpers

import "github.com/anchore/syft/syft/pkg"

func Description(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.ApkMetadata:
			return metadata.Description
		case pkg.NpmPackageJSONMetadata:
			return metadata.Description
		case pkg.RpmRepodata:
			return metadata.Description
			// TODO: add to support rpmdb
			// case pkg.RpmdbMetadata:
			// 	return metadata.Description
		}
	}
	return ""
}

func hasMetadata(p pkg.Package) bool {
	return p.Metadata != nil
}
