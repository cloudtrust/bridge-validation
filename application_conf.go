package validation

import (
	"encoding/json"
	"time"

	"github.com/cloudtrust/bridge-validation/io"
	"github.com/cloudtrust/keycloak-client"
)

// Configuration struct
type Configuration struct {
	AddrBridge           string                        `json:"addr_bridge"`
	AddrTokenProvider    string                        `json:"addr_token_provider"`
	TokenProviderTimeout string                        `json:"timeout,omitempty"`
	AuthzFilesFolder     string                        `json:"authz_files_folder"`
	TargetRealm          string                        `json:"target_realm"`
	SampleClientID       string                        `json:"sample_client_id"`
	TechnicalRealm       string                        `json:"technical_realm"`
	TechnicalUsername    string                        `json:"technical_username"`
	TechnicalPassword    string                        `json:"technical_password"`
	TechnicalClientID    string                        `json:"technical_client_id,omitempty"`
	Groups               map[string]GroupConfiguration `json:"groups"`
}

// GroupConfiguration struct
type GroupConfiguration struct {
	GroupID  string `json:"group_id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Authorizations type
type Authorizations map[string]map[string]map[string]interface{}

// LoadConfiguration loads the application configuration
func LoadConfiguration() (Configuration, error) {
	var confJSON, err = io.ReadFileBytes("conf/bridge-validation.conf")
	var res Configuration
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(confJSON, &res)
	return res, err
}

// ToKeycloakConfig returns a config for keycloak-client
func (c *Configuration) ToKeycloakConfig() keycloak.Config {
	var timeout = time.Second * 5
	if value, err := time.ParseDuration(c.TokenProviderTimeout); err == nil {
		timeout = value
	}
	return keycloak.Config{
		AddrTokenProvider: c.AddrTokenProvider,
		Timeout:           timeout,
	}
}

// NewAuthorizations creates a new Authorizations from its JSON representation
func NewAuthorizations(confJSON []byte) (Authorizations, error) {
	var authz Authorizations
	var err = json.Unmarshal(confJSON, &authz)
	return authz, err
}

// ExpectedAuthorization tells if an action is allowed
func (a Authorizations) ExpectedAuthorization(action, realm, targetGroup string) bool {
	if realmsAuthz, ok1 := a[action]; ok1 {
		if groupsAuthz, ok2 := realmsAuthz[realm]; ok2 {
			if targetGroup == "*" {
				return true
			}
			if _, ok3 := groupsAuthz[targetGroup]; ok3 {
				return true
			}
			if _, ok3 := groupsAuthz["*"]; ok3 {
				return true
			}
			return false
		}
	}
	return false
}
