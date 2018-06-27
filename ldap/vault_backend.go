package ldap

import (
	"github.com/samuel/go-ldap/ldap"
	"log"
	"net"
	"strings"
	"errors"
	"github.com/lumasepa/ldap2vault/vault"
)

type LdapClientCtx struct {
	AppIsAuthenticated bool
	Client   vault.VaultClient
}

type VaultBackend struct {
	VaultUrl string
}

func DNtoUser(dn string) (string, error){
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

func DNtoPath(dn string) (string, error){

	splited := strings.Split(dn, ",")
	if len(splited) < 1 {
		return "", errors.New("invalid dn")
	}

	pathElements := make([]string, len(splited))

	for i := len(splited) - 1; i >= 0; i++ {
		element := splited[i]
		splitedElement := strings.Split(element, "=")
		if len(splitedElement) != 2 {
			return "", errors.New("invalid cn")
		}
		pathElements = append(pathElements, splitedElement[1])
	}
	return strings.Join(pathElements, "/"), nil
}

func NewVaultBackend(vaultUrl string) VaultBackend {
	return VaultBackend{vaultUrl}
}

func (self VaultBackend) AuthenticateAppRole(ctx *LdapClientCtx, username string, password string) (*ldap.BindResponse, error) {
	log.Printf("Authenticating app user : %s", username)

	authToken, err := ctx.Client.AuthenticateApp(username, password)

	if err != nil {
		log.Printf("Error authenticating app user : %s : %s", username, err)
		return &ldap.BindResponse{
			BaseResponse: ldap.BaseResponse{
				Code:      ldap.ResultInvalidCredentials,
				MatchedDN: "",
				Message:   err.Error(),
			},
		}, nil
	}

	ctx.AppIsAuthenticated = true
	ctx.Client.SetToken(authToken)
	log.Printf("App user %s Authenticated", username)

	return &ldap.BindResponse{
		BaseResponse: ldap.BaseResponse{
			Code:      ldap.ResultSuccess,
			MatchedDN: "",
			Message:   "",
		},
	}, nil
}

func (self VaultBackend) AuthenticateVaultUser(ctx *LdapClientCtx, path string, password string) (*ldap.BindResponse, error) {
	log.Printf("Authenticating vault user : %s", path)

	isAuthenticated, err := ctx.Client.AuthenticateUser(path, password)

	if err != nil || ! isAuthenticated {
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
	client, err := vault.NewVaultClient(self.VaultUrl)
	if err != nil {
		return nil, err
	}
	ldapClientCtx := &LdapClientCtx{AppIsAuthenticated: false, Client: client}
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

	if ! ldapClientCtx.AppIsAuthenticated {
		username, err  := DNtoUser(req.DN)
		if err != nil {
			return &ldap.BindResponse{
				BaseResponse: ldap.BaseResponse{
					Code:      ldap.ResultInvalidDNSyntax,
					MatchedDN: "",
					Message:  err.Error(),
				},
			}, nil
		}
		return self.AuthenticateAppRole(ldapClientCtx, username, password)
	}else{
		path, err := DNtoPath(req.DN)
		if err != nil {
			return &ldap.BindResponse{
				BaseResponse: ldap.BaseResponse{
					Code:      ldap.ResultInvalidDNSyntax,
					MatchedDN: "",
					Message:  err.Error(),
				},
			}, nil
		}
		return self.AuthenticateVaultUser(ldapClientCtx, path, password)
	}
}

func (VaultBackend) Search(ctx ldap.Context, req *ldap.SearchRequest) (*ldap.SearchResponse, error) {
	log.Printf("SEARCH %+v\n", req)
	_, ok := ctx.(*LdapClientCtx)
	if !ok {
		return &ldap.SearchResponse{
			BaseResponse: ldap.BaseResponse{
				Code:      ldap.ResultNoSuchObject,
				MatchedDN: "",
				Message:  "",
			},
		}, nil
	}
	_, err  := DNtoUser(req.BaseDN)
	if err != nil {
		return &ldap.SearchResponse{
			BaseResponse: ldap.BaseResponse{
				Code:      ldap.ResultNoSuchObject,
				MatchedDN: "",
				Message:  err.Error(),
			},
		}, nil
	}


	return &ldap.SearchResponse{
		BaseResponse: ldap.BaseResponse{
			Code:      ldap.ResultSuccess,
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
