package login

import (
	"testing"
)

func Test_ldapAuth(t *testing.T) {
	dsl := LDAPLoginDSL{
		URL:          "ldap://192.168.3.254:389",
		BindUser:     "gitlab@yg.cn",
		BindPassword: "yangou20!*",
		UserDN:       "OU=IUNGO,DC=yg,DC=cn",
		UID:          "sAMAccountName",
		Attributes: LDAPAttribute{
			Username: "sAMAccountName",
			Email:    "mail",
			Name:     "name",
			Mobile:   "telephoneNumber",
		},
	}

	ldapAuth(dsl, "0005", "scnick1!")
}
