package config

import (
	"github.com/spf13/viper"
)

type format struct {
	IncludeCpe    bool `yaml:"include-cpe" json:"include-cpe" mapstructure:"include-cpe"`
	CountExternal bool `yaml:"count-external" json:"count-external" mapstructure:"count-external"`
}

func (cfg *format) parseConfigValues() error {
	return nil
}

func (cfg format) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("format.include-cpe", false)
	v.SetDefault("format.count-external", false)
}
