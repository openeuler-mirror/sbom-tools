package spdxhelpers

import "github.com/anchore/syft/syft/pkg"

func Supplier(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		// TODO: add to support rpmdb
		// case pkg.RpmdbMetadata:
		// 	return "Organization: " + metadata.vendor
		case pkg.RpmRepodata:
			return "Organization: " + metadata.Packager
		}
	}
	return ""
}
