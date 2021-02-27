# Connext Accounts

Account system for [connext.dev](https://connext.dev), with OAuth2 support. Requires a folder for icons (/icon) and a file for secrets (vars.json) which contains keys  
`smtp_url, email_addr, email_pass` (For sending emails to users)  
`owner_secret` (Code for setting users as owners)  
`session_secret` (Code for storing session/cookie data)  
`captcha_v3, captcha_v2` (reCaptcha v3 and v2 keys respectively)
