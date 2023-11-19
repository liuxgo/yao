package login

import (
	"time"

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
	return auth(account, password, sid)
}

func auth(value string, password string, sid string) maps.Map {

	// admin.user表三个唯一键username、email或者mobile均可登录
	user := model.Select("admin.user")
	rows, err := user.Get(model.QueryParam{
		Select: []interface{}{"id", "password", "name", "type", "username", "email", "mobile", "extra", "status"},
		Limit:  1,
		Wheres: []model.QueryWhere{
			{Column: "username", Value: value, Method: "orwhere"},
			{Column: "email", Value: value, Method: "orwhere"},
			{Column: "mobile", Value: value, Method: "orwhere"},
			{Column: "status", Value: "enabled"},
		},
	})

	if err != nil {
		exception.New("数据库查询错误", 500, "username", "email", "mobile").Throw()
	}

	if len(rows) == 0 {
		exception.New("用户不存在(%s)", 404, value).Throw()
	}

	row := rows[0]
	passwordHash := row.Get("password").(string)
	row.Del("password")

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		exception.New("登录密码错误 (%v)", 403, value).Throw()
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
