package main

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)


type Configuration struct {
	LdapListenPort int    `yaml:"ldap_listen_port"`
	LdapListenIp   string `yaml:"ldap_listen_ip"`
	VaultUrl       string `yaml:"vault_url"`
	AuthenticateApps bool `yaml:"authenticate_apps"`
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