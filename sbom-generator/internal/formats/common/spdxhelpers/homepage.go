package spdxhelpers

import "github.com/anchore/syft/syft/pkg"

func Homepage(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.GemMetadata:
			return metadata.Homepage
		case pkg.NpmPackageJSONMetadata:
			return metadata.Homepage
		// TODO: add to support rpmdb
		// case pkg.RpmdbMetadata:
		// 	return metadata.Homepage
		case pkg.RpmRepodata:
			return metadata.Homepage
		}
	}
	return ""
}
