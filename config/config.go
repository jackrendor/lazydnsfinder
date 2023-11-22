package config

import (
	"errors"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

var (
	DefaultConfigPath string
	Values            ConfigStruct
)

type ConfigStruct struct {
	Censys struct {
		APIID     string `yaml:"APIID"`
		APISECRET string `yaml:"APISECRET"`
	}
	Shodan struct {
		APIKEY string `yaml:"APIKEY"`
	}
}

func init() {
	configUserPath, configPathErr := os.UserConfigDir()
	if configPathErr != nil {
		log.Fatalln("[CONFIG] [init] [os.UserConfigDir]:", configPathErr.Error())
	}

	if err := os.MkdirAll(configUserPath, os.ModeDir); err != nil {
		log.Fatalln("[CONFIG] [init] [os.MkdirAll]:", err.Error())
	}

	DefaultConfigPath = filepath.Join(configUserPath, "lazydnsfinder.config")

	fileBytes, readErr := os.ReadFile(DefaultConfigPath)
	if readErr != nil {
		if errors.Is(readErr, os.ErrNotExist) {
			UpdateConfig()
		} else {
			log.Fatalln("[CONFIG] [init] [os.ReadFile]:", readErr.Error())
		}

	}

	if err := yaml.Unmarshal(fileBytes, &Values); err != nil {
		log.Fatalln("[CONFIG] [init] [yaml.Unmarshal]:", err.Error())
	}
}

func UpdateConfig() {
	dataBytes, marshalErr := yaml.Marshal(&Values)
	if marshalErr != nil {
		log.Fatalln("[CONFIG] [UpdateConfig] [yaml.Marshal]:", marshalErr.Error())
	}

	if err := os.WriteFile(DefaultConfigPath, dataBytes, 0660); err != nil {
		log.Fatalln("[CONFIG] [UpdateConfig] [os.WriteFile]:", err.Error())
	}
}
