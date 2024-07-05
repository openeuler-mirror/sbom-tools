package spdxhelpers

import "github.com/anchore/syft/syft/pkg"

func Summary(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		// case pkg.ApkMetadata:
		// 	return metadata.Summary
		// case pkg.NpmPackageJSONMetadata:
		// 	return metadata.Summary
		case pkg.RpmRepodata:
			return metadata.Summary
			// TODO: add to support rpmdb
			// case pkg.RpmdbMetadata:
			// 	return metadata.Description
		}
	}
	return ""
}
