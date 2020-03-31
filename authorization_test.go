package validation

import (
	"testing"

	errorhandler "github.com/cloudtrust/common-service/errors"

	"github.com/cloudtrust/bridge-validation/io"
	"github.com/stretchr/testify/assert"
)

func TestACF(t *testing.T) {
	errorhandler.SetEmitter("bridge-validator")

	var validator, err = NewAuthValidator()
	assert.Nil(t, err)

	var authz map[string]Authorizations
	authz, err = readAuthorizations(validator.Configuration.AuthzFilesFolder)
	assert.Nil(t, err)
	assert.NotNil(t, authz)
	assert.True(t, len(authz) > 0)

	for group := range authz {
		validator.Groups = append(validator.Groups, group)
	}

	for group, authzJSON := range authz {
		t.Run(group, func(t *testing.T) {
			assert.Nil(t, validator.CheckGroup(t, group, authzJSON))
		})
	}
	validator.Cleanup()
}

func readAuthorizations(filename string) (map[string]Authorizations, error) {
	var files, err = io.ReadJSONFiles(filename)
	if err != nil {
		return nil, err
	}
	var authz = make(map[string]Authorizations)
	// Dynamically add a group with no authorization
	authz["unknown"] = Authorizations{}

	for k, v := range files {
		var auth, err = NewAuthorizations(v)
		if err != nil {
			return nil, err
		}
		authz[k] = auth
	}

	return authz, nil
}
