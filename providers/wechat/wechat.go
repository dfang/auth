package wechat

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"reflect"

	"github.com/dfang/auth"
	"github.com/dfang/auth/auth_identity"
	"github.com/dfang/auth/claims"
	"github.com/qor/qor/utils"

	"github.com/chanxuehong/rand"
	"github.com/chanxuehong/session"
	"github.com/chanxuehong/sid"
	mpoauth2 "github.com/chanxuehong/wechat/mp/oauth2"
	"github.com/chanxuehong/wechat/oauth2"
)

// var (
// 	AuthorizeURL = "https://github.com/login/oauth/authorize"
// 	TokenURL     = "https://github.com/login/oauth/access_token"
// )

// const (
// 	wxAppId           = "wx56463c3ba7c843d8"                            // 填上自己的参数
// 	wxAppSecret       = "343937be9a016cc2393d59116847a891"              // 填上自己的参数
// 	oauth2RedirectURI = "http://be750378.ngrok.io/auth/wechat/callback" // 填上自己的参数
// 	oauth2Scope       = "snsapi_userinfo"                               // 填上自己的参数
// )

var (
	sessionStorage = session.New(20*60, 60*60)
	oauth2Endpoint oauth2.Endpoint
)

// GithubProvider provide login with github method
type WechatProvider struct {
	*Config
}

// Config github Config
type Config struct {
	// wx56463c3ba7c843d8
	// 343937be9a016cc2393d59116847a891
	// appID
	// appsecret
	AppID       string
	AppSecret   string
	RedirectURL string
	Scope       string
	// ClientID     string
	// ClientSecret string
	// AuthorizeURL string
	// TokenURL     string
	// RedirectURL  string
	AuthorizeHandler func(*auth.Context) (*claims.Claims, error)
	// Scopes []string
}

func New(config *Config) *WechatProvider {
	if config == nil {
		config = &Config{}
	}

	provider := &WechatProvider{Config: config}

	if config.AppID == "" {
		panic(errors.New("Wechat's AppID can't be blank"))
	}

	if config.AppSecret == "" {
		panic(errors.New("Wechat's AppSecret can't be blank"))
	}

	oauth2Endpoint = mpoauth2.NewEndpoint(config.AppID, config.AppSecret)

	if config.AuthorizeHandler == nil {
		config.AuthorizeHandler = func(context *auth.Context) (*claims.Claims, error) {
			var (
				schema       auth.Schema
				authInfo     auth_identity.Basic
				authIdentity = reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
				req          = context.Request
				tx           = context.Auth.GetDB(req)
			)

			w := context.Writer
			r := context.Request

			log.Println(r.RequestURI)

			cookie, err := r.Cookie("sid")
			if err != nil {
				io.WriteString(w, err.Error())
				log.Println(err)
				return nil, err
			}

			log.Println("cookie is ", cookie)

			session, err := sessionStorage.Get(cookie.Value)
			if err != nil {
				io.WriteString(w, err.Error())
				log.Println(err)
				return nil, err
			}

			log.Println("session is ", session)

			savedState := session.(string) // 一般是要序列化的, 这里保存在内存所以可以这么做

			queryValues, err := url.ParseQuery(r.URL.RawQuery)
			if err != nil {
				io.WriteString(w, err.Error())
				log.Println(err)
				return nil, err
			}

			code := queryValues.Get("code")
			if code == "" {
				log.Println("用户禁止授权")
				return nil, err
			}

			queryState := queryValues.Get("state")
			if queryState == "" {
				log.Println("state 参数为空")
				return nil, err
			}
			if savedState != queryState {
				str := fmt.Sprintf("state 不匹配, session 中的为 %q, url 传递过来的是 %q", savedState, queryState)
				io.WriteString(w, str)
				log.Println(str)
				return nil, err
			}

			oauth2Client := oauth2.Client{
				Endpoint: oauth2Endpoint,
			}
			token, err := oauth2Client.ExchangeToken(code)
			if err != nil {
				io.WriteString(w, err.Error())
				log.Println(err)
				return nil, err
			}
			log.Printf("token: %+v\r\n", token)

			userinfo, err := mpoauth2.GetUserInfo(token.AccessToken, token.OpenId, "", nil)
			if err != nil {
				io.WriteString(w, err.Error())
				log.Println(err)
				return nil, err
			}
			// json.NewEncoder(w).Encode(userinfo)
			log.Printf("userinfo: %+v\r\n", userinfo)

			authInfo.Provider = provider.GetName()
			authInfo.UID = fmt.Sprint(userinfo.OpenId)

			if !tx.Model(authIdentity).Where(
				map[string]interface{}{
					"provider": authInfo.Provider,
					"uid":      authInfo.UID,
				}).Scan(&authInfo).RecordNotFound() {
				return authInfo.ToClaims(), nil
			}
			// OpenId   string `json:"openid"`   // 用户的唯一标识
			// 	Nickname string `json:"nickname"` // 用户昵称
			// 	Sex      int    `json:"sex"`      // 用户的性别, 值为1时是男性, 值为2时是女性, 值为0时是未知
			// 	City     string `json:"city"`     // 普通用户个人资料填写的城市
			// 	Province string `json:"province"` // 用户个人资料填写的省份
			// 	Country  string `json:"country"`  // 国家, 如中国为CN

			// 	// 用户头像，最后一个数值代表正方形头像大小（有0、46、64、96、132数值可选，0代表640*640正方形头像），
			// 	// 用户没有头像时该项为空。若用户更换头像，原有头像URL将失效。
			// 	HeadImageURL string `json:"headimgurl,omitempty"`

			// 	Privilege []string `json:"privilege,omitempty"` // 用户特权信息，json 数组，如微信沃卡用户为（chinaunicom）
			//   UnionId   string   `json:"uni

			{
				schema.Provider = provider.GetName()
				schema.UID = fmt.Sprint(userinfo.OpenId)
				// schema.Nickname = userinfo.Nickname
				// schema.Sex = userinfo.Sex
				schema.Name = userinfo.Nickname
				// schema.Email = user.GetEmail()
				schema.Image = userinfo.HeadImageURL
				schema.RawInfo = userinfo
			}
			if _, userID, err := context.Auth.UserStorer.Save(&schema, context); err == nil {
				if userID != "" {
					authInfo.UserID = userID
				}
			} else {
				return nil, err
			}

			if err = tx.Where(
				map[string]interface{}{
					"provider": authInfo.Provider,
					"uid":      authInfo.UID,
				}).FirstOrCreate(authIdentity).Error; err == nil {
				return authInfo.ToClaims(), nil
			}
			return nil, err
		}
	}

	return provider
}

// GetName return provider name
func (WechatProvider) GetName() string {
	return "wechat"
}

// ConfigAuth config auth
func (provider WechatProvider) ConfigAuth(*auth.Auth) {
}

// Login implemented login with wechat provider
func (provider WechatProvider) Login(context *auth.Context) {
	// url := "/page1"
	// http.Redirect(context.Writer, context.Request, url, http.StatusFound)
	var config = provider.Config
	w, r := context.Writer, context.Request

	sid := sid.New()
	state := string(rand.NewHex())

	if err := sessionStorage.Add(sid, state); err != nil {
		io.WriteString(w, err.Error())
		log.Println(err)
		return
	}

	cookie := http.Cookie{
		Name:     "sid",
		Value:    sid,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

	// AuthCodeURL := mpoauth2.AuthCodeURL(wxAppId, oauth2RedirectURI, oauth2Scope, state)
	AuthCodeURL := mpoauth2.AuthCodeURL(config.AppID, config.RedirectURL, config.Scope, state)
	log.Println("AuthCodeURL:", AuthCodeURL)

	http.Redirect(w, r, AuthCodeURL, http.StatusFound)
	// http.Redirect(context.Writer, context.Request, AuthCodeURL, http.StatusFound)
}

// Logout implemented logout with wechat provider
func (WechatProvider) Logout(context *auth.Context) {
}

// Register implemented register with wechat provider
func (provider WechatProvider) Register(context *auth.Context) {
	provider.Login(context)
}

// Callback implement Callback with wechat provider
func (provider WechatProvider) Callback(context *auth.Context) {
	context.Auth.LoginHandler(context, provider.AuthorizeHandler)
}

// ServeHTTP implement ServeHTTP with github provider
func (WechatProvider) ServeHTTP(*auth.Context) {
}

// UserInfo wechat user info structure
type UserInfo struct {
	OpenId   string `json:"openid"`   // 用户的唯一标识
	Nickname string `json:"nickname"` // 用户昵称
	Sex      int    `json:"sex"`      // 用户的性别, 值为1时是男性, 值为2时是女性, 值为0时是未知
	City     string `json:"city"`     // 普通用户个人资料填写的城市
	Province string `json:"province"` // 用户个人资料填写的省份
	Country  string `json:"country"`  // 国家, 如中国为CN

	// 用户头像，最后一个数值代表正方形头像大小（有0、46、64、96、132数值可选，0代表640*640正方形头像），
	// 用户没有头像时该项为空。若用户更换头像，原有头像URL将失效。
	HeadImageURL string `json:"headimgurl,omitempty"`

	// Privilege []string `json:"privilege,omitempty"` // 用户特权信息，json 数组，如微信沃卡用户为（chinaunicom）
	UnionId string `json:"unionid,omitempty"` // 只有在用户将公众号绑定到微信开放平台帐号后，才会出现该字段。
}
