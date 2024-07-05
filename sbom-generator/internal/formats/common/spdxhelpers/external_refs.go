package spdxhelpers

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

const checksumPrefix = "pkg:maven/sha1"

func ExternalRefs(p pkg.Package, externalCounter *ExternalCounter) (externalRefs []ExternalRef) {
	externalRefs = make([]ExternalRef, 0)

	for _, c := range p.CPEs {
		externalRefs = append(externalRefs, ExternalRef{
			ReferenceCategory: SecurityReferenceCategory,
			ReferenceLocator:  pkg.CPEString(c),
			ReferenceType:     Cpe23ExternalRefType,
		})
	}

	if p.PURL != "" {
		externalRefs = append(externalRefs, ExternalRef{
			ReferenceCategory: PackageManagerReferenceCategory,
			ReferenceLocator:  p.PURL,
			ReferenceType:     PurlExternalRefType,
		})
	}

	for _, providesPurl := range p.ProvidesPurls {
		externalRefs = append(externalRefs, ExternalRef{
			ReferenceCategory: ProvideManagerReferenceCategory,
			ReferenceLocator:  providesPurl,
			ReferenceType:     PurlExternalRefType,
		})
		externalCounter.ProvideMap[providesPurl] = p.Name
	}

	pkgExternalList := []string{}
	for _, externalPurl := range p.ExtPkgPurls {
		externalRef := ExternalRef{
			ReferenceCategory: ExternalManagerReferenceCategory,
			ReferenceLocator:  externalPurl,
		}
		if strings.HasPrefix(externalPurl, checksumPrefix) {
			externalRef.ReferenceType = ChecksumExternalRefType
		} else {
			externalRef.ReferenceType = PurlExternalRefType
		}

		externalRefs = append(externalRefs, externalRef)
		externalCounter.ExternalMap[externalPurl] = p.Name
		pkgExternalList = append(pkgExternalList, externalPurl)
	}
	externalCounter.ExternalPkgMap[p.Name] = pkgExternalList

	return externalRefs
}
