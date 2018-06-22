package main

import (
	"github.com/samuel/go-ldap/ldap"
)

func main() {
	var iamBackend ldap.Backend = IAMBackend{}
	server, err := ldap.NewServer(iamBackend, nil)

	if err != nil {
		panic(err)
	}

	err = server.Serve("tcp", "0.0.0.0:389")

	if err != nil {
		panic(err)
	}
}
