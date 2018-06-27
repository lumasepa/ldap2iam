package vault
import (
	vault "github.com/hashicorp/vault/api"
	"net/http"
)

type VaultClient struct {
	vault.Client
}

func NewVaultClient(url string) (VaultClient, error) {
	client, err := vault.NewClient(&vault.Config{Address: url, HttpClient: &http.Client{}})
	if err != nil {
		return VaultClient{}, err
	}
	return VaultClient{ *client}, nil
}


func (self VaultClient) AuthenticateUser(path string, password string) (bool, error) {
	secret, err  := self.Client.Logical().Read(path)
	if err != nil {
		return false, err
	}

	if vaultStoredPassword, ok := secret.Data["password"]; ok {
		if vaultStoredPassword == password {
			return true, nil
		}
	}
	return false, nil
}

func (self VaultClient) AuthenticateApp(RoleId string, SecretId string) (authToken string, err error) {
	options := map[string]interface{}{
		"role_id": RoleId,
		"secret_id": SecretId,
	}
	path := "auth/approle/login"
	secret, err := self.Client.Logical().Write(path, options)
	if err != nil {
		return
	}
	return secret.TokenID()
}

func (self VaultClient) GetUserData(path string, attributes []string) (result map[string]interface{}, err error) {
	// TODO Filter password
	result = make(map[string]interface{}, len(attributes))
	_, err = self.Client.Logical().List(path)
	if err != nil {
		return
	}
	return result, nil
}
