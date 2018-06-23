package main

import (
	"github.com/samuel/go-ldap/ldap"
	"flag"
	"strconv"
	"log"
)

func main() {
	confFilePath := flag.String("c", "/etc/ldap2vault.conf.yaml", "configuration file")

	flag.Parse()

	conf, err := readConf(*confFilePath)

	if err != nil {
		panic(err)
	}

	var vaultBackend ldap.Backend = NewVaultBackend(conf.VaultUrl, conf.AuthenticateApps)
	server, err := ldap.NewServer(vaultBackend, nil)

	if err != nil {
		panic(err)
	}
	listenAddr := conf.LdapListenIp + ":" +  strconv.Itoa(conf.LdapListenPort)

	log.Printf("Ldap Server listening in %s" , listenAddr)
	log.Printf("Vault backend url %s" , conf.VaultUrl)

	err = server.Serve("tcp", listenAddr)

	if err != nil {
		panic(err)
	}
}
