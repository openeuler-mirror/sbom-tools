package spdxhelpers

import (
	"fmt"

	"github.com/spf13/viper"
)

type ExternalCounter struct {
	ProvideMap     map[string]string
	ExternalMap    map[string]string
	ExternalPkgMap map[string][]string
}

func (count ExternalCounter) PrintCountInfo() {
	v := viper.GetViper()
	if !v.GetBool("format.count-external") {
		return
	}

	fmt.Println("---------externalCounter, print externals info of image---------")
	for k := range count.ExternalMap {
		if _, exists := count.ProvideMap[k]; exists {
			continue
		}
		fmt.Println(k)
	}

	fmt.Println("---------externalCounter, print externals info of package---------")
	for k, v := range count.ExternalPkgMap {
		if v == nil || len(v) <= 0 {
			continue
		}

		fmt.Println("package name:" + k)
		for _, extName := range v {
			if _, exists := count.ProvideMap[extName]; exists {
				continue
			}
			fmt.Println(extName)
		}
	}
}
