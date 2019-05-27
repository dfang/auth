# 如何使用微信网页授权

微信公众号提供测试账号，无需注册申请公众号就可以测试

1. 登录 https://mp.weixin.qq.com/debug/cgi-bin/sandboxinfo?action=showinfo&t=sandbox/index

记住 appID 和 appSecret, 并设置 网页授权获取用户基本信息 授权回调页面域名

2. 配置 wechat provider

```
  Auth.RegisterProvider(wechat.New(&wechat.Config{
    AppID:        "<appID>",
    AppSecret:    "<appSecret>",
    RedirectURL:  "http://xxxxx.ngrok.io/auth/wechat/callback",
  }))
```

3.

假如 go run main.go -> 打开的是 localhost:9000
运行 ngrok 代理 `ngrok http 900`, 记住 url
第一步需要填 xxx.ngrok.io 域名, 不带 http 或 https, 填域名就可以了
第二步中的 RedirectURL
