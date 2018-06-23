package main

import (
	"github.com/samuel/go-ldap/ldap"
	vault "github.com/hashicorp/vault/api"
	"log"
	"net"
	"strings"
	"errors"
	"fmt"
	"net/http"
)

type LdapClientCtx struct {
	AppIsAuthenticated bool
}

type VaultBackend struct {
	vaultUrl string
	AuthenticateApps bool
	client   vault.Client

}

func parseDN(dn string) (string, error){
	splited := strings.Split(dn, ",")
	if len(splited) < 1 {
		return "", errors.New("invalid dn")
	}
	username := strings.Split(splited[0], "=")
	if len(username) != 2 {
		return "", errors.New("invalid cn")
	}
	return username[1], nil
}

func NewVaultBackend(vaultUrl string, authenticateApps bool) VaultBackend {
	client, err := vault.NewClient(&vault.Config{Address: vaultUrl, HttpClient: &http.Client{}})
	if err != nil {
		panic(err)
	}

	return VaultBackend{vaultUrl, authenticateApps,*client}
}

func (self VaultBackend) VaultAuthenticate(username string, password string) (*vault.Secret, error) {
	options := map[string]interface{}{
		"password": password,
	}

	path := fmt.Sprintf("auth/userpass/login/%s", username)
	return self.client.Logical().Write(path, options)
}


func (self VaultBackend) AuthenticateAppUser(ctx *LdapClientCtx, username string, password string) (*ldap.BindResponse, error) {
	log.Printf("Authenticating app user : %s", username)

	_, err := self.VaultAuthenticate(username, password)

	if err != nil {
		return &ldap.BindResponse{
			BaseResponse: ldap.BaseResponse{
				Code:      ldap.ResultInvalidCredentials,
				MatchedDN: "",
				Message:   err.Error(),
			},
		}, nil
	}

	ctx.AppIsAuthenticated = true
	return &ldap.BindResponse{
		BaseResponse: ldap.BaseResponse{
			Code:      ldap.ResultSuccess,
			MatchedDN: "",
			Message:   "",
		},
	}, nil
}

func (self VaultBackend) AuthenticateVaultUser(username string, password string) (*ldap.BindResponse, error) {
	log.Printf("Authenticating vault user : %s", username)

	_, err := self.VaultAuthenticate(username, password)

	if err != nil {
		return &ldap.BindResponse{
			BaseResponse: ldap.BaseResponse{
				Code:      ldap.ResultInvalidCredentials,
				MatchedDN: "",
				Message:   err.Error(),
			},
		}, nil
	}

	return &ldap.BindResponse{
		BaseResponse: ldap.BaseResponse{
			Code:      ldap.ResultSuccess,
			MatchedDN: "",
			Message:   "",
		},
	}, nil
}

//
// LDAP Backend interface
//
func (self VaultBackend) Connect(addr net.Addr) (ldap.Context, error) {
	ldapClientCtx := &LdapClientCtx{AppIsAuthenticated: ! self.AuthenticateApps}
	return ldapClientCtx, nil
}


func (self VaultBackend) Bind(ctx ldap.Context, req *ldap.BindRequest) (*ldap.BindResponse, error) {
	password := string(req.Password)
	req.Password = nil
	log.Printf("BIND %+v\n", req)

	ldapClientCtx, ok := ctx.(*LdapClientCtx)
	if ! ok {
		return &ldap.BindResponse{
			BaseResponse: ldap.BaseResponse{
				Code:      ldap.ResultInappropriateAuthentication,
				MatchedDN: "",
				Message:  "",
			},
		}, nil
	}

	username, err  := parseDN(req.DN)
	if err != nil {
		return &ldap.BindResponse{
			BaseResponse: ldap.BaseResponse{
				Code:      ldap.ResultInappropriateAuthentication,
				MatchedDN: "",
				Message:  err.Error(),
			},
		}, nil
	}

	if ! ldapClientCtx.AppIsAuthenticated {
		return self.AuthenticateAppUser(ldapClientCtx, username, password)
	}else{
		return self.AuthenticateVaultUser(username, password)
	}
}

func (VaultBackend) Search(ctx ldap.Context, req *ldap.SearchRequest) (*ldap.SearchResponse, error) {
	log.Printf("SEARCH %+v\n", req)
	ldapClientCtx, _ := ctx.(*LdapClientCtx)
	log.Print(ldapClientCtx)
	return &ldap.SearchResponse{
		BaseResponse: ldap.BaseResponse{
			Code:      ldap.ResultSuccess, //LDAPResultNoSuchObject,
			MatchedDN: "",
			Message:   "",
		},
		Results: []*ldap.SearchResult{
			&ldap.SearchResult{
				DN: "cn=admin,dc=example,dc=com",
				Attributes: map[string][][]byte{
					"objectClass": [][]byte{[]byte("person")},
					"cn":          [][]byte{[]byte("admin")},
					"uid":         [][]byte{[]byte("123")},
				},
			},
		},
	}, nil
}


func (VaultBackend) Disconnect(ctx ldap.Context) {}

func (VaultBackend) Add(ctx ldap.Context, req *ldap.AddRequest) (*ldap.AddResponse, error) {
	log.Printf("ADD %+v\n", req)
	return &ldap.AddResponse{}, nil
}

func (VaultBackend) Delete(ctx ldap.Context, req *ldap.DeleteRequest) (*ldap.DeleteResponse, error) {
	log.Printf("DELETE %+v\n", req)
	return &ldap.DeleteResponse{}, nil
}

func (VaultBackend) ExtendedRequest(ctx ldap.Context, req *ldap.ExtendedRequest) (*ldap.ExtendedResponse, error) {
	log.Printf("EXTENDED %+v\n", req)
	return nil, ldap.ErrProtocolError("unsupported extended request")
}

func (VaultBackend) Modify(ctx ldap.Context, req *ldap.ModifyRequest) (*ldap.ModifyResponse, error) {
	log.Printf("MODIFY dn=%s\n", req.DN)
	return &ldap.ModifyResponse{}, nil
}

func (VaultBackend) ModifyDN(ctx ldap.Context, req *ldap.ModifyDNRequest) (*ldap.ModifyDNResponse, error) {
	log.Printf("MODIFYDN %+v\n", req)
	return &ldap.ModifyDNResponse{}, nil
}

func (VaultBackend) PasswordModify(ctx ldap.Context, req *ldap.PasswordModifyRequest) ([]byte, error) {
	log.Printf("PASSWORD MODIFY %+v\n", req)
	return []byte("genpass"), nil
}

func (VaultBackend) Whoami(ctx ldap.Context) (string, error) {
	log.Println("WHOAMI")
	return "cn=someone,o=somewhere", nil
}
