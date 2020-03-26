This project is written as a unit test and must be configured to hit an instance of keycloak-bridge.
Its aim is to call each method of the management API with all possible profiles to check the configured authorizations.

Expected authorizations should be stored in JSON files in the conf folder, each file is considered to describe a specific Keycloak group.
Each group should be configured in the bridge-validation.conf file (its ID and one of its users)