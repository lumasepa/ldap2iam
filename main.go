package main

import (
	"github.com/samuel/go-ldap/ldap"
)

func main() {
	conf, err := readConf("./ldap2iam.conf.yaml")

	if err != nil {
		panic(err)
	}

	var iamBackend ldap.Backend = IAMBackend{}
	server, err := ldap.NewServer(iamBackend, nil)

	if err != nil {
		panic(err)
	}

	err = server.Serve("tcp", conf.LdapListenIp + ":" + string(conf.LdapListenPort))

	if err != nil {
		panic(err)
	}
}
