# PhishingAlert
A Golang fork of x0rz's phishing_cather linked to a Telegram bot

NOTE: this is a (more rough and simplistic) fork of [x0rz's phishing_catcher](https://github.com/x0rz/phishing_catcher) all the credits for this project goes to him.

PhishingAlert catches malicious phishing domain names using certstream and sends the report via telegram.

## How to
- [Create a telegram bot](https://core.telegram.org/bots)
- Set `BOT_TOKEN` env var with the APIKEY of your bot
- Set `TG_CHAT` env var with the group ID of your group/channel/privatechat/whatever
- Run PhishingAlert

## Building
`go get github.com/BurntSushi/toml github.com/CaliDog/certstream-go github.com/deckarep/golang-set github.com/joeguo/tldextract github.com/texttheater/golang-levenshtein/levenshtein gopkg.in/telegram-bot-api.v4`

`go build`


Please feel free to contribute and/or give a feedback


