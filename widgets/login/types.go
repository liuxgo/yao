package login

// DSL the login DSL
type DSL struct {
	ID              string               `json:"id,omitempty"`
	Name            string               `json:"name,omitempty"`
	Action          ActionDSL            `json:"action,omitempty"`
	Layout          LayoutDSL            `json:"layout,omitempty"`
	ThirdPartyLogin []ThirdPartyLoginDSL `json:"thirdPartyLogin,omitempty"`
	LDAP            LDAPLoginDSL         `json:"ldap,omitempty"`
}

// ActionDSL the login action DSL
type ActionDSL struct {
	Process string        `json:"process,omitempty"`
	Args    []interface{} `json:"args,omitempty"`
}

// LayoutDSL the login page layoutDSL
type LayoutDSL struct {
	Entry   string `json:"entry,omitempty"`
	Captcha string `json:"captcha,omitempty"`
	Cover   string `json:"cover,omitempty"`
	Slogan  string `json:"slogan,omitempty"`
	Site    string `json:"site,omitempty"`
}

// ThirdPartyLoginDSL the thirdparty login url
type ThirdPartyLoginDSL struct {
	Title string `json:"title,omitempty"`
	Href  string `json:"href,omitempty"`
	Icon  string `json:"icon,omitempty"`
	Blank bool   `json:"blank,omitempty"`
}

type LDAPAttribute struct {
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Mobile   string `json:"mobile,omitempty"`
	Name     string `json:"name,omitempty"`
}

type LDAPLoginDSL struct {
	URL          string        `json:"url,omitempty"`
	BindUser     string        `json:"bindUser,omitempty"`
	BindPassword string        `json:"bindPassword,omitempty"`
	UserDN       string        `json:"userDN,omitempty"`
	UID          string        `json:"uid,omitempty"`
	Attributes   LDAPAttribute `json:"attributes,omitempty"`
}
