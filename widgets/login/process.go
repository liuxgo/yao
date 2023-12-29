package login

import (
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/yaoapp/gou/model"
	"github.com/yaoapp/gou/process"
	"github.com/yaoapp/gou/session"
	"github.com/yaoapp/kun/any"
	"github.com/yaoapp/kun/exception"
	"github.com/yaoapp/kun/log"
	"github.com/yaoapp/kun/maps"
	"github.com/yaoapp/yao/config"
	"github.com/yaoapp/yao/helper"
	"golang.org/x/crypto/bcrypt"
)

// Export process

func exportProcess() {
	process.Register("yao.login.admin", processLoginAdmin)
	process.Register("yao.login.ldap", processLoginLDAP)
}

// processLoginAdmin yao.admin.login 用户登录
func processLoginAdmin(process *process.Process) interface{} {
	process.ValidateArgNums(2)
	user := process.ArgsString(0)
	payload := process.ArgsMap(1).Dot()
	log.With(log.F{"payload": payload}).Debug("processLoginAdmin")

	isCaptcha := Logins[user].Layout.Captcha != ""
	if isCaptcha {
		id := any.Of(payload.Get("captcha.id")).CString()
		value := any.Of(payload.Get("captcha.code")).CString()
		if id == "" {
			exception.New("请输入验证码ID", 400).Ctx(maps.Map{"id": id, "code": value}).Throw()
		}

		if value == "" {
			exception.New("请输入验证码", 400).Ctx(maps.Map{"id": id, "code": value}).Throw()
		}

		if !helper.CaptchaValidate(id, value) {
			log.With(log.F{"id": id, "code": value}).Debug("ProcessLogin")
			exception.New("验证码不正确", 403).Ctx(maps.Map{"id": id, "code": value}).Throw()
			return nil
		}
	}

	sid := session.ID()
	if csid, ok := payload["sid"].(string); ok {
		sid = csid
	}

	account := any.Of(payload.Get("account")).CString()
	password := any.Of(payload.Get("password")).CString()
	return auth(account, password, sid, true)
}

// processLoginLDAP yao.login.ldap 用户LDAP登录
func processLoginLDAP(process *process.Process) interface{} {
	process.ValidateArgNums(2)
	user := process.ArgsString(0)
	payload := process.ArgsMap(1).Dot()
	log.With(log.F{"payload": payload}).Debug("processLoginLDAP")

	isCaptcha := Logins[user].Layout.Captcha != ""
	if isCaptcha {
		id := any.Of(payload.Get("captcha.id")).CString()
		value := any.Of(payload.Get("captcha.code")).CString()
		if id == "" {
			exception.New("请输入验证码ID", 400).Ctx(maps.Map{"id": id, "code": value}).Throw()
		}

		if value == "" {
			exception.New("请输入验证码", 400).Ctx(maps.Map{"id": id, "code": value}).Throw()
		}

		if !helper.CaptchaValidate(id, value) {
			log.With(log.F{"id": id, "code": value}).Debug("ProcessLogin")
			exception.New("验证码不正确", 403).Ctx(maps.Map{"id": id, "code": value}).Throw()
			return nil
		}
	}

	sid := session.ID()
	if csid, ok := payload["sid"].(string); ok {
		sid = csid
	}

	account := any.Of(payload.Get("account")).CString()
	password := any.Of(payload.Get("password")).CString()

	userInfo, _ := ldapAuth(Logins[user].LDAP, account, password)
	_ = saveLDAPUser(userInfo)

	return auth(account, password, sid, false)

}

func auth(account string, password string, sid string, isCompareHashPassword bool) maps.Map {

	// admin.user表三个唯一键username、email或者mobile均可登录
	user := model.Select("admin.user")
	rows, err := user.Get(model.QueryParam{
		Select: []interface{}{"id", "password", "name", "type", "username", "email", "mobile", "extra", "status"},
		Limit:  1,
		Wheres: []model.QueryWhere{
			{Column: "username", Value: account, Method: "orwhere"},
			{Column: "email", Value: account, Method: "orwhere"},
			{Column: "mobile", Value: account, Method: "orwhere"},
			{Column: "status", Value: "enabled"},
		},
	})

	if err != nil {
		exception.New("数据库查询错误", 500, "username", "email", "mobile").Throw()
	}

	if len(rows) == 0 {
		exception.New("用户不存在(%s)", 404, account).Throw()
	}

	row := rows[0]
	if isCompareHashPassword {
		passwordHash := row.Get("password").(string)
		row.Del("password")

		err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
		if err != nil {
			exception.New("登录密码错误 (%v)", 403, account).Throw()
		}
	}

	expiresAt := time.Now().Unix() + 3600*8

	// token := MakeToken(row, expiresAt)
	id := any.Of(row.Get("id")).CInt()
	token := helper.JwtMake(id, map[string]interface{}{}, map[string]interface{}{
		"expires_at": expiresAt,
		"sid":        sid,
		"issuer":     "yao",
	})
	log.Debug("[login] auth sid=%s", sid)
	session.Global().Expire(time.Duration(token.ExpiresAt)*time.Second).ID(sid).Set("user_id", id)
	session.Global().Expire(time.Duration(token.ExpiresAt)*time.Second).ID(sid).Set("user", row)
	session.Global().Expire(time.Duration(token.ExpiresAt)*time.Second).ID(sid).Set("issuer", "yao")

	studio := map[string]interface{}{}
	if config.Conf.Mode == "development" {

		studioToken := helper.JwtMake(id, map[string]interface{}{}, map[string]interface{}{
			"expires_at": expiresAt,
			"sid":        sid,
			"issuer":     "yao",
		}, []byte(config.Conf.Studio.Secret))

		studio["port"] = config.Conf.Studio.Port
		studio["token"] = studioToken.Token
		studio["expires_at"] = studioToken.ExpiresAt
	}

	// 读取菜单
	menus := process.New("yao.app.menu").WithSID(sid).Run()
	return maps.Map{
		"expires_at": token.ExpiresAt,
		"token":      token.Token,
		"user":       row,
		"menus":      menus,
		"studio":     studio,
	}
}

// ldap鉴权
func ldapAuth(dsl LDAPLoginDSL, account, password string) (maps.MapStrAny, error) {
	// 连接ldap服务器
	l, err := ldap.DialURL(dsl.URL)
	if err != nil {
		exception.New("LDAP服务器连接失败", 500, dsl.URL).Throw()
	}
	defer l.Close()

	// 绑定ldap管理用户
	err = l.Bind(dsl.BindUser, dsl.BindPassword)
	if err != nil {
		if err != nil {
			exception.New("LDAP配置不正确", 500).Throw()
		}
	}

	// 1. 先对用户进行搜索，是否在ldap中
	filter := fmt.Sprintf("(&(objectClass=person)(%s=%s))", dsl.UID, account)
	attributes := []string{dsl.Attributes.Username, dsl.Attributes.Name, dsl.Attributes.Email, dsl.Attributes.Mobile}
	searchRequest := ldap.NewSearchRequest(
		dsl.UserDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		nil,
	)
	sr, err := l.Search(searchRequest)
	if err != nil || len(sr.Entries) == 0 {
		exception.New("用户不存在(%s)", 404, account).Throw()
	}

	// 2. 进行二次bind，验证用户pass是否正确
	userDN := sr.Entries[0].DN
	err = l.Bind(userDN, password)
	if err != nil {
		exception.New("登录密码错误 (%v)", 403, account).Throw()
	}

	userAttributes := make(map[string]string)
	userAttributes[dsl.Attributes.Username] = "username"
	userAttributes[dsl.Attributes.Name] = "name"
	userAttributes[dsl.Attributes.Email] = "email"
	userAttributes[dsl.Attributes.Mobile] = "mobile"

	result := maps.MakeMapStrAny()
	for _, attr := range sr.Entries[0].Attributes {
		result[userAttributes[attr.Name]] = attr.Values[0]
	}

	return result, nil
}

// 保存ldap查询的用户数据，不存在数据则创建数据
func saveLDAPUser(userInfo maps.MapStrAny) error {
	user := model.Select("admin.user")

	rows, err := user.Get(model.QueryParam{
		Select: []interface{}{"id", "password", "name", "type", "username", "email", "mobile", "extra", "status"},
		Limit:  1,
		Wheres: []model.QueryWhere{
			{Column: "username", Value: userInfo["username"], Method: "orwhere"},
			{Column: "email", Value: userInfo["email"], Method: "orwhere"},
			{Column: "mobile", Value: userInfo["mobile"], Method: "orwhere"},
		},
	})

	if err != nil {
		exception.New("数据库查询错误", 500, "username", "email", "mobile").Throw()
	}

	if len(rows) != 0 {
		userInfo["id"] = any.Of(rows[0].Get("id")).CInt()
	}

	_, err = user.Save(userInfo)
	if err != nil {
		exception.New("保存用户数据失败", 500).Throw()
	}
	return nil
}
