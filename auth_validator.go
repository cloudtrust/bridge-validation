package validation

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cloudtrust/bridge-validation/bridge"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/validation"
	"github.com/cloudtrust/keycloak-client"
	"github.com/stretchr/testify/assert"
)

// User struct
type User struct {
	ID       string
	Username string
	Groups   []string
}

// AuthValidator struct
type AuthValidator struct {
	Configuration Configuration
	Bridge        bridge.Client
	AdminToken    keycloak.OidcTokenProvider
	MgmtActions   map[string]string
	Groups        []string
	Logger        log.Logger
	AnyValue      int
}

// NewAuthValidator creates a new AuthValidator
func NewAuthValidator() (AuthValidator, error) {
	var conf, err = LoadConfiguration()
	if err != nil {
		return AuthValidator{}, err
	}
	var logger = log.NewNopLogger()

	return AuthValidator{
		Configuration: conf,
		Bridge:        bridge.NewBridgeClient(conf.AddrBridge),
		AdminToken:    keycloak.NewOidcTokenProvider(conf.ToKeycloakConfig(), conf.TechnicalRealm, conf.TechnicalUsername, conf.TechnicalPassword, conf.TechnicalClientID, logger),
		Logger:        logger,
		AnyValue:      time.Now().Nanosecond() % 10000,
	}, nil
}

// GetActions load available actions in Bridge/Management
func (v *AuthValidator) GetActions() (map[string]string, error) {
	if v.MgmtActions != nil {
		return v.MgmtActions, nil
	}

	var conf = v.Configuration
	var accessToken, err = v.GetOIDCToken(conf.TechnicalRealm, conf.TechnicalUsername, conf.TechnicalPassword)
	if err != nil {
		return nil, err
	}

	var actions map[string]string
	actions, err = v.Bridge.GetActionsResponse(accessToken)
	if err != nil {
		return nil, err
	}

	v.MgmtActions = actions

	return actions, nil
}

// GetOIDCToken returns an OIDC token for the given user
func (v *AuthValidator) GetOIDCToken(realm, username, password string) (string, error) {
	var oidcTokenProvider = keycloak.NewOidcTokenProvider(v.Configuration.ToKeycloakConfig(), realm, username, password, v.Configuration.TechnicalClientID, v.Logger)
	return oidcTokenProvider.ProvideToken(context.Background())
}

// CheckGroup checks authorizations for a given group
func (v *AuthValidator) CheckGroup(t *testing.T, group string, authz Authorizations) error {
	var groupConfig GroupConfiguration
	if value, ok := v.Configuration.Groups[group]; ok {
		groupConfig = value
	} else {
		return fmt.Errorf("Group %s not configured", group)
	}

	var accessToken, err = v.GetOIDCToken(v.Configuration.TargetRealm, groupConfig.Username, groupConfig.Password)
	if err != nil {
		return fmt.Errorf("Can't get token for %s/%s: %s", group, groupConfig.Username, err.Error())
	}

	var actions map[string]string
	actions, err = v.GetActions()
	if err != nil {
		return err
	}

	preventActions := []string{
		// Out of scope
		"MGMT_GetUserRealmBackOfficeConfiguration", "MGMT_AssignableGroupsToUser",
		"MGMT_UpdateRealmCustomConfiguration", "MGMT_UpdateRealmAdminConfiguration", "MGMT_GetRealmBackOfficeConfiguration",
		// Don't know how to delete group without breaking test environment. It could be
		// done anyway as currently nobody is allowed to do this, but it wouldn't be safe
		"MGMT_DeleteGroup",
	}
	for action, scope := range actions {
		if !validation.IsStringInSlice(preventActions, action) {
			t.Run(action, func(t *testing.T) {
				switch scope {
				case "realm":
					v.checkScope(t, group, accessToken, action, authz, group, "*")
				case "user":
					v.checkScopeUser(t, group, accessToken, action, authz)
				case "group":
					v.checkScopeGroup(t, group, accessToken, action, authz)
				}
			})
		}
	}

	return nil
}

func (v *AuthValidator) checkScope(t *testing.T, group, accessToken, action string, authz Authorizations, targetGroup, authzGroup string) {
	var actualAuthzCode = v.executeAction(accessToken, action, targetGroup)
	if actualAuthzCode == 0 {
		assert.Fail(t, "Unexpected response")
	} else {
		var actualAuthz = true
		if actualAuthzCode == 403 {
			actualAuthz = false
		}
		var expectedAuthz = authz.ExpectedAuthorization(action, v.Configuration.TargetRealm, authzGroup)
		assert.Equal(t, expectedAuthz, actualAuthz)
	}
}

func (v *AuthValidator) checkScopeUser(t *testing.T, group, accessToken, action string, authz Authorizations) {
	v.checkScopeGroup(t, group, accessToken, action, authz)
}

func (v *AuthValidator) checkScopeGroup(t *testing.T, group, accessToken, action string, authz Authorizations) {
	for _, targetGroup := range v.Groups {
		t.Run(targetGroup, func(t *testing.T) {
			v.checkScope(t, group, accessToken, action, authz, targetGroup, targetGroup)
		})
	}
}

func (v *AuthValidator) executeAction(accessToken, action string, targetGroup string) int {
	switch action {
	case "MGMT_GetActions":
		return v.Bridge.GetActions(accessToken)
	case "MGMT_GetRealms":
		return v.Bridge.GetRealms(accessToken)
	case "MGMT_GetRealm":
		return v.Bridge.GetRealm(accessToken, v.Configuration.TargetRealm)
	case "MGMT_GetRealmCustomConfiguration":
		return v.Bridge.GetRealmCustomConfiguration(accessToken, v.Configuration.TargetRealm)
	case "MGMT_GetRealmAdminConfiguration":
		return v.Bridge.GetRealmAdminConfiguration(accessToken, v.Configuration.TargetRealm)
	case "MGMT_GetRealmBackOfficeConfiguration":
		return v.Bridge.GetRealmBackOfficeConfiguration(accessToken, v.Configuration.TargetRealm)
	case "MGMT_UpdateRealmBackOfficeConfiguration":
		return v.Bridge.UpdateRealmBackOfficeConfiguration(accessToken, v.Configuration.TargetRealm)
	case "MGMT_GetUserRealmBackOfficeConfiguration":
		return v.Bridge.GetUserRealmBackOfficeConfiguration(accessToken, v.Configuration.TargetRealm)
	case "MGMT_GetClients":
		return v.Bridge.GetClients(accessToken, v.Configuration.TargetRealm)
	case "MGMT_GetClient":
		return v.Bridge.GetClient(accessToken, v.Configuration.TargetRealm, v.Configuration.SampleClientID)
	case "MGMT_GetClientRoles":
		return v.Bridge.GetClientRoles(accessToken, v.Configuration.TargetRealm, v.Configuration.SampleClientID)
	case "MGMT_GetRequiredActions":
		return v.Bridge.GetRequiredActions(accessToken, v.Configuration.TargetRealm)
	case "MGMT_GetUsers":
		return v.Bridge.GetUsers(accessToken, v.Configuration.TargetRealm, v.Configuration.Groups[targetGroup].GroupID)
	case "MGMT_GetUser":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.GetUser(accessToken, v.Configuration.TargetRealm, user.ID)
		})
	case "MGMT_CreateUser":
		var groupID = v.Configuration.Groups[targetGroup].GroupID
		var username = v.randomName("user-" + targetGroup + "-")
		var code, _, _ = v.Bridge.CreateUserResponse(accessToken, v.Configuration.TargetRealm, username, groupID)
		return code
	case "MGMT_UpdateUser":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.UpdateUser(accessToken, v.Configuration.TargetRealm, user.ID, user.Username, user.Groups[0])
		})
	case "MGMT_DeleteUser":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.DeleteUser(accessToken, v.Configuration.TargetRealm, user.ID)
		})
	case "MGMT_GetUpdateUser":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.UpdateUser(accessToken, v.Configuration.TargetRealm, user.ID, user.Username, targetGroup)
		})
	case "MGMT_GetUserAccountStatus":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.GetUserAccountStatus(accessToken, v.Configuration.TargetRealm, user.ID)
		})
	case "MGMT_GetCredentialsForUser":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.GetCredentialsForUser(accessToken, v.Configuration.TargetRealm, user.ID)
		})
	case "MGMT_DeleteCredentialsForUser":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			var credID = user.ID // will be a non valid credential identifier
			return v.Bridge.DeleteCredentialsForUser(accessToken, v.Configuration.TargetRealm, user.ID, credID)
		})
	case "MGMT_CreateRecoveryCode":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.CreateRecoveryCode(accessToken, v.Configuration.TargetRealm, user.ID)
		})
	case "MGMT_CreateShadowUser":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.CreateShadowUser(accessToken, v.Configuration.TargetRealm, user.ID)
		})
	case "MGMT_GetRolesOfUser":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.GetRolesOfUser(accessToken, v.Configuration.TargetRealm, user.ID)
		})
	case "MGMT_GetGroupsOfUser":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.GetGroupsOfUser(accessToken, v.Configuration.TargetRealm, user.ID)
		})
	case "MGMT_SetGroupsToUser":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.SetGroupsOfUser(accessToken, v.Configuration.TargetRealm, user.ID, []string{})
		})
	case "MGMT_GetAvailableTrustIDGroups":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.GetAvailableTrustIDGroups(accessToken, v.Configuration.TargetRealm)
		})
	case "MGMT_GetTrustIDGroups":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.GetTrustIDGroupsOfUser(accessToken, v.Configuration.TargetRealm, user.ID)
		})
	case "MGMT_SetTrustIDGroups":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.SetTrustIDGroupsToUser(accessToken, v.Configuration.TargetRealm, user.ID, []string{})
		})
	case "MGMT_ResetPassword":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.ResetPassword(accessToken, v.Configuration.TargetRealm, user.ID)
		})
	case "MGMT_ExecuteActionsEmail":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.ExecuteActionsEmail(accessToken, v.Configuration.TargetRealm, user.ID)
		})
	case "MGMT_SendNewEnrolmentCode":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.SendNewEnrolmentCode(accessToken, v.Configuration.TargetRealm, user.ID)
		})
	case "MGMT_SendReminderEmail":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.SendReminderEmail(accessToken, v.Configuration.TargetRealm, user.ID)
		})
	case "MGMT_ResetSmsCounter":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.ResetSmsCounter(accessToken, v.Configuration.TargetRealm, user.ID)
		})
	case "MGMT_ClearUserLoginFailures":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.ClearUserLoginFailures(accessToken, v.Configuration.TargetRealm, user.ID)
		})
	case "MGMT_GetClientRolesForUser":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.GetClientRolesForUser(accessToken, v.Configuration.TargetRealm, user.ID, v.Configuration.SampleClientID)
		})
	case "MGMT_AddClientRolesToUser":
		return v.withUser(v.Configuration.TargetRealm, targetGroup, func(user User) int {
			return v.Bridge.AddClientRolesForUser(accessToken, v.Configuration.TargetRealm, user.ID, v.Configuration.SampleClientID)
		})
	case "MGMT_CreateClientRole":
		return v.Bridge.CreateClientRole(accessToken, v.Configuration.TargetRealm, v.Configuration.SampleClientID, v.randomName("role-"))
	case "MGMT_GetRoles":
		return v.Bridge.GetRoles(accessToken, v.Configuration.TargetRealm)
	case "MGMT_GetRole":
		var roleID, err = v.chooseAnyRoleID(v.Configuration.TargetRealm)
		if err != nil {
			return 0
		}
		return v.Bridge.GetRole(accessToken, v.Configuration.TargetRealm, roleID)
	case "MGMT_GetGroups":
		return v.Bridge.GetGroups(accessToken, v.Configuration.TargetRealm)
	case "MGMT_CreateGroup":
		return v.Bridge.CreateGroup(accessToken, v.Configuration.TargetRealm, v.randomName("group-"))
	case "MGMT_GetAuthorizations":
		return v.Bridge.GetAuthorizations(accessToken, v.Configuration.TargetRealm, v.Configuration.Groups[targetGroup].GroupID)
	case "MGMT_UpdateAuthorizations":
		return v.Bridge.UpdateAuthorizations(accessToken, v.Configuration.TargetRealm, v.Configuration.Groups[targetGroup].GroupID)
	default:
		return 0
	}
}

func (v *AuthValidator) chooseAnyRoleID(realmName string) (string, error) {
	var accessToken, err = v.AdminToken.ProvideToken(context.Background())
	if err != nil {
		return "", err
	}
	return v.Bridge.GetAnyRoleID(accessToken, realmName)
}

func (v *AuthValidator) withUser(realmName, group string, callback func(User) int) int {
	var accessToken, errToken = v.AdminToken.ProvideToken(context.Background())
	if errToken != nil {
		return 0
	}
	var groupID = v.Configuration.Groups[group].GroupID
	var username = v.randomName("user-" + group + "-")
	var _, userID, err = v.Bridge.CreateUserResponse(accessToken, realmName, username, groupID)
	if err != nil || userID == "" {
		return 0
	}
	var user = User{
		ID:       userID,
		Username: username,
		Groups:   []string{groupID},
	}
	var result = callback(user)
	v.Bridge.DeleteUser(accessToken, v.Configuration.TargetRealm, userID)
	return result
}

func (v *AuthValidator) randomName(radix string) string {
	v.AnyValue++
	return fmt.Sprintf("%s%d", radix, v.AnyValue)
}

// Cleanup is the final application cleanup
func (v *AuthValidator) Cleanup() {
	var accessToken, errToken = v.AdminToken.ProvideToken(context.Background())
	if errToken != nil {
		return
	}
	v.cleanupUsers(accessToken)
	v.cleanupGroups(accessToken)
	v.cleanupRoles(accessToken)
}

func (v *AuthValidator) cleanupUsers(accessToken string) {
	var total = 0
	for _, grpName := range v.Groups {
		var goOnCleaning = true
		for goOnCleaning {
			goOnCleaning = false
			var users, _ = v.Bridge.GetUsersResponse(accessToken, v.Configuration.TargetRealm, v.Configuration.Groups[grpName].GroupID)
			for key, value := range users {
				if strings.HasPrefix(value, "user-") {
					if v.Bridge.DeleteUser(accessToken, v.Configuration.TargetRealm, key) == 200 {
						total++
						goOnCleaning = true
					}
				}
			}
		}
	}
	fmt.Printf("Removed %d users\n", total)
}

func (v *AuthValidator) cleanupGroups(accessToken string) {
}

func (v *AuthValidator) cleanupRoles(accessToken string) {
}
