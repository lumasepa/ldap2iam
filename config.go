package main

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type AppUser struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type IAMConfig struct {
	UsersWhitelist []string `yaml:"users_whitelist"`
	ApiKey string `yaml:"api_key"`
	ApiSecret string `yaml:"api_secret"`
	Region string `yaml:"region"`
}

type Configuration struct {
	LdapListenPort int `yaml:"ldap_listen_port"`
	LdapListenIp string `yaml:"ldap_listen_ip"`
	AppUsers []AppUser `yaml:"app_users"`
	IAM IAMConfig `yaml:"iam"`
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