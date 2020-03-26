package bridge

import (
	"errors"
	"strings"

	"github.com/cloudtrust/keycloak-client"
	"gopkg.in/h2non/gentleman.v2/plugins/body"
	"gopkg.in/h2non/gentleman.v2/plugins/query"
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	pathActions                     = "/management/actions"
	pathRealms                      = "/management/realms"
	pathRealm                       = pathRealms + "/:realm"
	pathRealmCustomConf             = pathRealm + "/configuration"
	pathRealmAdminConf              = pathRealm + "/admin-configuration"
	pathUsers                       = pathRealm + "/users"
	pathUser                        = pathUsers + "/:user"
	pathUserBackOfficeConfiguration = pathUser + "/"
	pathClients                     = pathRealm + "/clients"
	pathClient                      = pathClients + "/:client"
	pathClientRoles                 = pathClient + "/roles"
	pathRoles                       = pathRealm + "/roles"
	pathRole                        = pathRealm + "/roles-by-id/:role"
	pathGroups                      = pathRealm + "/groups"
	pathGroup                       = pathGroups + "/:group"
	pathRequiredActions             = pathRealm + "/required-actions"
	pathRealmBackOfficeConf         = pathRealm + "/backoffice-configuration/groups"
	pathAuthorizations              = pathGroup + "/authorizations"
	pathCredentials                 = pathUser + "/credentials"
)

// GetUsersResponse method
func (c *Client) GetUsersResponse(accessToken, realmName, groupID string) (map[string]string, error) {
	var users keycloak.UsersPageRepresentation
	var res = make(map[string]string)
	var _, err = c.get(accessToken, &users, url.Path(pathUsers), url.Param("realm", realmName), query.Add("groupIds", groupID))
	if err != nil {
		return res, err
	}
	for _, user := range users.Users {
		res[*user.Id] = *user.Username
	}
	return res, nil
}

// GetActionsResponse method
func (c *Client) GetActionsResponse(accessToken string) (map[string]string, error) {
	var actions []ActionRepresentation
	var _, err = c.get(accessToken, &actions, url.Path(pathActions))
	if err != nil {
		return nil, err
	}

	var result = make(map[string]string)
	for _, action := range actions {
		result[action.Name] = action.Scope
	}
	return result, err
}

// GetRolesResponse method
func (c *Client) GetRolesResponse(accessToken, realmName string) ([]RoleRepresentation, error) {
	var roles []RoleRepresentation
	var _, err = c.get(accessToken, &roles, url.Path(pathRoles), url.Param("realm", realmName))
	return roles, err
}

// GetAnyRoleID method
func (c *Client) GetAnyRoleID(accessToken, realmName string) (string, error) {
	var roles, err = c.GetRolesResponse(accessToken, realmName)
	if err != nil {
		return "", err
	}
	if len(roles) == 0 {
		return "", errors.New("No role found")
	}
	return *roles[0].ID, nil
}

// CreateUserResponse method
func (c *Client) CreateUserResponse(accessToken, realmName, username, targetGroup string) (int, string, error) {
	var groups = []string{targetGroup}
	var user = keycloak.UserRepresentation{
		Username: &username,
		Groups:   &groups,
	}
	var code, id, err = c.post(accessToken, url.Path(pathUsers), url.Param("realm", realmName), body.JSON(user))
	var parts = strings.Split(id, "/")
	return code, parts[len(parts)-1], err
}

// GetActions method
func (c *Client) GetActions(accessToken string) int {
	return c.getStatus(accessToken, url.Path(pathActions))
}

// GetRealms method
func (c *Client) GetRealms(accessToken string) int {
	return c.getStatus(accessToken, url.Path(pathRealms))
}

// GetRealm method
func (c *Client) GetRealm(accessToken, realmName string) int {
	return c.getStatus(accessToken, url.Path(pathRealm), url.Param("realm", realmName))
}

// GetRealmCustomConfiguration method
func (c *Client) GetRealmCustomConfiguration(accessToken, realmName string) int {
	return c.getStatus(accessToken, url.Path(pathRealmCustomConf), url.Param("realm", realmName))
}

// GetRealmAdminConfiguration method
func (c *Client) GetRealmAdminConfiguration(accessToken, realmName string) int {
	return c.getStatus(accessToken, url.Path(pathRealmAdminConf), url.Param("realm", realmName))
}

// GetRealmBackOfficeConfiguration method
func (c *Client) GetRealmBackOfficeConfiguration(accessToken, realmName string) int {
	return c.getStatus(accessToken, url.Path(pathRealmBackOfficeConf), url.Param("realm", realmName))
}

// UpdateRealmBackOfficeConfiguration method
func (c *Client) UpdateRealmBackOfficeConfiguration(accessToken, realmName string) int {
	var conf = make(map[string]string)
	return c.putStatus(accessToken, url.Path(pathRealmBackOfficeConf), url.Param("realm", realmName), query.Add("groupName", "name"), body.JSON(conf))
}

// GetUserRealmBackOfficeConfiguration method
func (c *Client) GetUserRealmBackOfficeConfiguration(accessToken, realmName string) int {
	return c.getStatus(accessToken, url.Path(pathRealm+"/backoffice-configuration"), url.Param("realm", realmName))
}

// GetClients method
func (c *Client) GetClients(accessToken, realmName string) int {
	return c.getStatus(accessToken, url.Path(pathClients), url.Param("realm", realmName))
}

// GetClient method
func (c *Client) GetClient(accessToken, realmName, clientID string) int {
	return c.getStatus(accessToken, url.Path(pathClient), url.Param("realm", realmName), url.Param("client", clientID))
}

// GetClientRoles method
func (c *Client) GetClientRoles(accessToken, realmName, clientID string) int {
	return c.getStatus(accessToken, url.Path(pathClientRoles), url.Param("realm", realmName), url.Param("client", clientID))
}

// GetRoles method
func (c *Client) GetRoles(accessToken, realmName string) int {
	return c.getStatus(accessToken, url.Path(pathRoles), url.Param("realm", realmName))
}

// GetRole method
func (c *Client) GetRole(accessToken, realmName, roleID string) int {
	return c.getStatus(accessToken, url.Path(pathRole), url.Param("realm", realmName), url.Param("role", roleID))
}

// GetGroups method
func (c *Client) GetGroups(accessToken, realmName string) int {
	return c.getStatus(accessToken, url.Path(pathGroups), url.Param("realm", realmName))
}

// GetGroup method
func (c *Client) GetGroup(accessToken, realmName, groupID string) int {
	return c.getStatus(accessToken, url.Path(pathGroup), url.Param("realm", realmName), url.Param("group", groupID))
}

// CreateGroup method
func (c *Client) CreateGroup(accessToken, realmName, groupName string) int {
	var group = keycloak.GroupRepresentation{Name: &groupName}
	return c.postStatus(accessToken, url.Path(pathGroups), url.Param("realm", realmName), body.JSON(group))
}

// GetAuthorizations method
func (c *Client) GetAuthorizations(accessToken, realmName, groupID string) int {
	return c.getStatus(accessToken, url.Path(pathAuthorizations), url.Param("realm", realmName), url.Param("group", groupID))
}

// UpdateAuthorizations method
func (c *Client) UpdateAuthorizations(accessToken, realmName, groupID string) int {
	var authz = map[string]string{}
	return c.putStatus(accessToken, url.Path(pathAuthorizations), url.Param("realm", realmName), url.Param("group", groupID), body.JSON(authz))
}

// GetRequiredActions method
func (c *Client) GetRequiredActions(accessToken, realmName string) int {
	return c.getStatus(accessToken, url.Path(pathRequiredActions), url.Param("realm", realmName))
}

// GetUsers method
func (c *Client) GetUsers(accessToken, realmName, groupID string) int {
	return c.getStatus(accessToken, url.Path(pathUsers), url.Param("realm", realmName), query.Add("groupIds", groupID))
}

// GetUser method
func (c *Client) GetUser(accessToken, realmName, userID string) int {
	return c.getStatus(accessToken, url.Path(pathUser), url.Param("realm", realmName), url.Param("user", userID))
}

// DeleteUser method
func (c *Client) DeleteUser(accessToken, realmName, userID string) int {
	return c.deleteStatus(accessToken, url.Path(pathUser), url.Param("realm", realmName), url.Param("user", userID))
}

// UpdateUser method
func (c *Client) UpdateUser(accessToken, realmName, userID, username string, group string) int {
	var groups = []string{group}
	var user = keycloak.UserRepresentation{
		Username:  &username,
		Groups:    &groups,
		FirstName: &username,
	}
	return c.putStatus(accessToken, url.Path(pathUser), url.Param("realm", realmName), url.Param("user", userID), body.JSON(user))
}

// GetUserAccountStatus method
func (c *Client) GetUserAccountStatus(accessToken, realmName, userID string) int {
	return c.getStatus(accessToken, url.Path(pathUser+"/status"), url.Param("realm", realmName), url.Param("user", userID))
}

// GetCredentialsForUser method
func (c *Client) GetCredentialsForUser(accessToken, realmName, userID string) int {
	return c.getStatus(accessToken, url.Path(pathCredentials), url.Param("realm", realmName), url.Param("user", userID))
}

// DeleteCredentialsForUser method
func (c *Client) DeleteCredentialsForUser(accessToken, realmName, userID, credID string) int {
	return c.deleteStatus(accessToken, url.Path(pathCredentials+"/:credential"),
		url.Param("realm", realmName), url.Param("user", userID), url.Param("credential", credID))
}

// CreateRecoveryCode method
func (c *Client) CreateRecoveryCode(accessToken, realmName, userID string) int {
	return c.postStatus(accessToken, url.Path(pathUser+"/recovery-code"), url.Param("realm", realmName), url.Param("user", userID))
}

// CreateShadowUser method
func (c *Client) CreateShadowUser(accessToken, realmName, userID string) int {
	var provider = "any-value"
	var user = map[string]string{
		"userID":   userID,
		"username": realmName, // why not
	}
	return c.postStatus(accessToken, url.Path(pathUser+"/federated-identity/:provider"),
		url.Param("realm", realmName), url.Param("user", userID), url.Param("provider", provider), body.JSON(user))
}

// GetRolesOfUser method
func (c *Client) GetRolesOfUser(accessToken, realmName, userID string) int {
	return c.getStatus(accessToken, url.Path(pathUser+"/roles"), url.Param("realm", realmName), url.Param("user", userID))
}

// GetGroupsOfUser method
func (c *Client) GetGroupsOfUser(accessToken, realmName, userID string) int {
	return c.getStatus(accessToken, url.Path(pathUser+"/groups"), url.Param("realm", realmName), url.Param("user", userID))
}

// SetGroupsOfUser method
func (c *Client) SetGroupsOfUser(accessToken, realmName, userID string, groupIDs []string) int {
	return c.putStatus(accessToken, url.Path(pathUser+"/groups"), url.Param("realm", realmName), url.Param("user", userID), body.JSON(groupIDs))
}

// GetAvailableTrustIDGroups method
func (c *Client) GetAvailableTrustIDGroups(accessToken, realmName string) int {
	return c.getStatus(accessToken, url.Path(pathRealm+"/trustIdGroups"), url.Param("realm", realmName))
}

// GetTrustIDGroupsOfUser method
func (c *Client) GetTrustIDGroupsOfUser(accessToken, realmName, userID string) int {
	return c.getStatus(accessToken, url.Path(pathUser+"/trustIdGroups"), url.Param("realm", realmName), url.Param("user", userID))
}

// SetTrustIDGroupsToUser method
func (c *Client) SetTrustIDGroupsToUser(accessToken, realmName, userID string, groupIDs []string) int {
	return c.putStatus(accessToken, url.Path(pathUser+"/trustIdGroups"), url.Param("realm", realmName), url.Param("user", userID), body.JSON(groupIDs))
}

// ResetPassword method
func (c *Client) ResetPassword(accessToken, realmName, userID string) int {
	var password = map[string]string{"value": "password"}
	return c.putStatus(accessToken, url.Path(pathUser+"/reset-password"), url.Param("realm", realmName), url.Param("user", userID), body.JSON(password))
}

// ExecuteActionsEmail method
func (c *Client) ExecuteActionsEmail(accessToken, realmName, userID string) int {
	return c.putStatus(accessToken, url.Path(pathUser+"/execute-actions-email"), url.Param("realm", realmName), url.Param("user", userID), body.JSON([]string{}))
}

// SendNewEnrolmentCode method
func (c *Client) SendNewEnrolmentCode(accessToken, realmName, userID string) int {
	return c.postStatus(accessToken, url.Path(pathUser+"/send-new-enrolment-code"), url.Param("realm", realmName), url.Param("user", userID), body.JSON([]string{}))
}

// SendReminderEmail method
func (c *Client) SendReminderEmail(accessToken, realmName, userID string) int {
	return c.postStatus(accessToken, url.Path(pathUser+"/send-reminder-email"), url.Param("realm", realmName), url.Param("user", userID), body.JSON([]string{}))
}

// ResetSmsCounter method
func (c *Client) ResetSmsCounter(accessToken, realmName, userID string) int {
	return c.putStatus(accessToken, url.Path(pathUser+"/reset-sms-counter"), url.Param("realm", realmName), url.Param("user", userID), body.JSON([]string{}))
}

// ClearUserLoginFailures method
func (c *Client) ClearUserLoginFailures(accessToken, realmName, userID string) int {
	return c.deleteStatus(accessToken, url.Path(pathUser+"/clear-login-failures"), url.Param("realm", realmName), url.Param("user", userID), body.JSON([]string{}))
}

// CreateClientRole method
func (c *Client) CreateClientRole(accessToken, realmName, clientID, roleName string) int {
	var role = RoleRepresentation{Name: &roleName}
	return c.postStatus(accessToken, url.Path(pathClient+"/roles"), url.Param("realm", realmName), url.Param("client", clientID), body.JSON(role))
}

// GetClientRolesForUser method
func (c *Client) GetClientRolesForUser(accessToken, realmName, userID, clientID string) int {
	return c.getStatus(accessToken, url.Path(pathUser+"/role-mappings/clients/:client"), url.Param("realm", realmName), url.Param("user", userID), url.Param("client", clientID))
}

// AddClientRolesForUser method
func (c *Client) AddClientRolesForUser(accessToken, realmName, userID, clientID string) int {
	return c.getStatus(accessToken, url.Path(pathUser+"/role-mappings/clients/:clientID"), url.Param("realm", realmName), url.Param("user", userID), url.Param("clientID", clientID), body.JSON([]string{}))
}
