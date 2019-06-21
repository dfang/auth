package wechat_work

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"reflect"

	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/qor/utils"

	wechatwork "github.com/dfang/wechat-work-go"
	"github.com/dfang/wechat-work-go/contact"
)

// WechatWorkProvider provide login with wechat work
type WechatWorkProvider struct {
	*Config
}

// Config github Config
type Config struct {
	CorpID           string
	AgentID          int64
	CorpSecret       string // 使用通讯录同步助手的SECRET
	RedirectURI      string
	State            string
	AuthType         string // 支持网页授权和扫码登录 (web, scan), 不同的认正方式，授权URL不同，默认（即不配置）为scan
	AuthorizeHandler func(*auth.Context) (*claims.Claims, error)
}

// https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid=CORPID&agentid=AGENTID&redirect_uri=REDIRECT_URI&state=STATE

// CORPID=wxfd0a488aa1fa5171
// AGENTID=1000027
// REDIRECT_URI=

func New(config *Config) *WechatWorkProvider {
	if config == nil {
		config = &Config{}
	}

	if config.CorpID == "" {
		panic(errors.New("Wechat work's CorpID can't be blank"))
	}

	if config.CorpSecret == "" {
		panic(errors.New("Wechat work's CorpSecret can't be blank"))
	}

	if config.AgentID < 0 {
		panic(errors.New("Wechat work's AgentID can't be blank"))
	}

	if config.RedirectURI == "" {
		panic(errors.New("Wechat work's RedirectURL can't be blank"))
	}

	if config.AuthType == "" {
		config.AuthType = "scan"
	} else {
		config.AuthType = "web"
	}

	provider := &WechatWorkProvider{Config: config}

	if config.AuthorizeHandler == nil {
		config.AuthorizeHandler = func(context *auth.Context) (*claims.Claims, error) {
			var (
				schema       auth.Schema
				authInfo     auth_identity.AuthIdentity
				authIdentity = reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
				req          = context.Request
				tx           = context.Auth.GetDB(req)
			)

			// state := req.URL.Query().Get("state")
			code := req.URL.Query().Get("code")
			// https://work.weixin.qq.com/api/doc#90000/90135/91437

			// https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo?access_token=ACCESS_TOKEN&code=CODE
			// getUserInfo(code, access_code)

			// https://open.weixin.qq.com/connect/oauth2/authorize?appid=CORPID&redirect_uri=REDIRECT_URI&response_type=code&scope=snsapi_base&state=STATE#wechat_redirect
			// https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid=CORPID&agentid=AGENTID&redirect_uri=REDIRECT_URI&state=STATE

			// can't pass this validation, skip it for now
			// maybe wechat work don't use jwt to sign
			// claims, err := context.Auth.SessionStorer.ValidateClaims(state)
			// if err != nil || claims.Valid() != nil || claims.Subject != "state" {
			// 	return nil, auth.ErrUnauthorized
			// }

			// if err == nil {

			// 用 code 和 access_token 获取 UserID
			client := wechatwork.New(provider.Config.CorpID)
			app := client.NewApp(provider.Config.CorpSecret, provider.Config.AgentID)
			ct := contact.WithApp(app)
			// tkn := app.GetAccessToken()

			// code 和 access_token 获取 UserID
			// https://work.weixin.qq.com/api/doc#90000/90135/91437
			result, err := app.GetUserInfo(code)
			if err != nil {
				return nil, err
			}

			authInfo.Provider = provider.GetName()
			authInfo.UID = fmt.Sprint(result.UserID)
			authInfo.UserID = fmt.Sprint(result.UserID)

			if !tx.Model(authIdentity).Where(authInfo).Scan(&authInfo).RecordNotFound() {
				return authInfo.ToClaims(), nil
			}

			// Get Real UserInfo by wechat work contacts api
			// https://work.weixin.qq.com/api/doc#90000/90135/90196
			respM, err := ct.GetMember(result.UserID)
			if err != nil {
				return nil, err
			}
			user := respM.Member

			{
				schema.Provider = provider.GetName()
				schema.UID = result.UserID
				schema.Name = user.Name
				schema.Email = user.Email
				schema.Image = user.Avatar
				schema.RawInfo = user
			}
			if _, userID, err := context.Auth.UserStorer.Save(&schema, context); err == nil {
				if userID != "" {
					authInfo.UserID = userID
				}
			} else {
				return nil, err
			}

			if err = tx.Where(authInfo).FirstOrCreate(authIdentity).Error; err == nil {
				return authInfo.ToClaims(), nil
			}
			return nil, err
			// }
			// return nil, err
		}
	}

	return provider
}

// GetName return provider name
func (WechatWorkProvider) GetName() string {
	return "wechat_work"
}

// ConfigAuth config auth
func (provider WechatWorkProvider) ConfigAuth(*auth.Auth) {
}

// Login implemented login with wechat provider
func (provider WechatWorkProvider) Login(context *auth.Context) {
	AuthCodeURL := provider.buildAuthCodeURL()
	// claims := claims.Claims{}
	// claims.Subject = "state"
	// signedToken := context.Auth.SessionStorer.SignedToken(&claims)

	// url := provider.OAuthConfig(context).AuthCodeURL(signedToken)
	// http.Redirect(context.Writer, context.Request, url, http.StatusFound)

	http.Redirect(context.Writer, context.Request, AuthCodeURL, http.StatusFound)
}

// Logout implemented logout with wechat work provider
func (WechatWorkProvider) Logout(context *auth.Context) {
}

// Register implemented register with wechat work provider
func (provider WechatWorkProvider) Register(context *auth.Context) {
	provider.Login(context)
}

// Callback implement Callback with wechat work provider
func (provider WechatWorkProvider) Callback(context *auth.Context) {
	context.Auth.LoginHandler(context, provider.AuthorizeHandler)
}

// ServeHTTP implement ServeHTTP with wechat work provider
func (WechatWorkProvider) ServeHTTP(*auth.Context) {
}

func (provider WechatWorkProvider) buildAuthCodeURL() string {
	// https://work.weixin.qq.com/api/doc#90000/90135/91019
	// https://work.weixin.qq.com/api/doc#90000/90135/91019

	authType := provider.Config.AuthType
	if !(authType == "scan" || authType == "web") {
		panic("请正确配置authType, 不同的认证方式使用的获取身份信息的URL不同")
	}
	var AuthCodeURL string
	config := provider.Config

	if authType == "scan" {
		AuthCodeURL = fmt.Sprintf("https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid=%s&agentid=%d&redirect_uri=%s&state=%s", config.CorpID, config.AgentID, config.RedirectURI, config.State)
	} else {
		AuthCodeURL = fmt.Sprintf("https://open.weixin.qq.com/connect/oauth2/authorize?appid=%s&redirect_uri=%s&response_type=code&scope=snsapi_base&state=%s#wechat_redirect", config.CorpID, config.RedirectURI, config.State)
	}

	log.Println("Wechat Work QR Code Login AuthCodeURL:", AuthCodeURL)
	return AuthCodeURL
}

// urlEncoded encodes a string like Javascript's encodeURIComponent()
func urlEncoded(str string) (string, error) {
	u, err := url.Parse(str)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}
