package pkg

import (
	"sort"
)

func mergePURLs(a, b []string) (result []string) {
	aPURLs := make(map[string]string)

	for _, aPURL := range a {
		aPURLs[aPURL] = "0"
		result = append(result, aPURL)
	}

	for _, bPURL := range b {
		if _, exists := aPURLs[bPURL]; !exists {
			result = append(result, bPURL)
		}
	}

	sort.Strings(result)
	return result
}
