package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/samuel/go-ldap/ldap"
	"log"
	"net"
)

type IAMBackend struct {
	iamconn *iam.IAM
}

func (self IAMBackend) searchIAMUser(userName string) (error, *iam.User) {
	req := &iam.GetUserInput{
		UserName: aws.String(userName),
	}

	log.Printf("[DEBUG] Reading IAM User: %s", req)
	resp, err := self.iamconn.GetUser(req)
	if err != nil {
		return err, nil
	}

	return nil, resp.User
}

func (IAMBackend) Add(ctx ldap.Context, req *ldap.AddRequest) (*ldap.AddResponse, error) {
	fmt.Printf("ADD %+v\n", req)
	return &ldap.AddResponse{}, nil
}

func (IAMBackend) Bind(ctx ldap.Context, req *ldap.BindRequest) (*ldap.BindResponse, error) {
	fmt.Printf("BIND %+v\n", req)
	return &ldap.BindResponse{
		BaseResponse: ldap.BaseResponse{
			Code:      ldap.ResultSuccess,
			MatchedDN: "",
			Message:   "",
		},
	}, nil
}

func (IAMBackend) Connect(addr net.Addr) (ldap.Context, error) {
	return nil, nil
}

func (IAMBackend) Disconnect(ctx ldap.Context) {
}

func (IAMBackend) Delete(ctx ldap.Context, req *ldap.DeleteRequest) (*ldap.DeleteResponse, error) {
	fmt.Printf("DELETE %+v\n", req)
	return &ldap.DeleteResponse{}, nil
}

func (IAMBackend) ExtendedRequest(ctx ldap.Context, req *ldap.ExtendedRequest) (*ldap.ExtendedResponse, error) {
	fmt.Printf("EXTENDED %+v\n", req)
	return nil, ldap.ErrProtocolError("unsupported extended request")
}

func (IAMBackend) Modify(ctx ldap.Context, req *ldap.ModifyRequest) (*ldap.ModifyResponse, error) {
	fmt.Printf("MODIFY dn=%s\n", req.DN)
	for _, m := range req.Mods {
		fmt.Printf("\t%s %s\n", m.Type, m.Name)
		for _, v := range m.Values {
			fmt.Printf("\t\t%s\n", string(v))
		}
	}
	return &ldap.ModifyResponse{}, nil
}

func (IAMBackend) ModifyDN(ctx ldap.Context, req *ldap.ModifyDNRequest) (*ldap.ModifyDNResponse, error) {
	fmt.Printf("MODIFYDN %+v\n", req)
	return &ldap.ModifyDNResponse{}, nil
}

func (IAMBackend) PasswordModify(ctx ldap.Context, req *ldap.PasswordModifyRequest) ([]byte, error) {
	fmt.Printf("PASSWORD MODIFY %+v\n", req)
	return []byte("genpass"), nil
}

func (IAMBackend) Search(ctx ldap.Context, req *ldap.SearchRequest) (*ldap.SearchResponse, error) {
	fmt.Printf("SEARCH %+v\n", req)

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

func (IAMBackend) Whoami(ctx ldap.Context) (string, error) {
	fmt.Println("WHOAMI")
	return "cn=someone,o=somewhere", nil
}
