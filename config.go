package main

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type VaultConfig struct {
	Url       string `yaml:"url"`
	SecretId  string `yaml:"secret_id"`
	RoleId    string `yaml:"role_id"`
	UsersPath string `yaml:"users_path"`
}

type Configuration struct {
	LdapListenPort int    `yaml:"ldap_listen_port"`
	LdapListenIp   string `yaml:"ldap_listen_ip"`
	AuthenticateApps 	bool `yaml:"authenticate_apps"`
	VaultConfiguration VaultConfig `yaml:"vault"`
}

func readConf(confPath string) (*Configuration, error) {

	conf := &Configuration{}
	confFileContent, err := ioutil.ReadFile(confPath)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(confFileContent, conf)
	if err != nil {
		return nil, err
	}
	return conf, nil
}