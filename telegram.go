package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/deckarep/golang-set"
	"gopkg.in/telegram-bot-api.v4"
)

func sendTelegramNotify(domainsSet mapset.Set) {
	bot, err := tgbotapi.NewBotAPI(os.Getenv("BOT_TOKEN"))
	if err != nil {
		log.Panic(err)
	}
	message := ""
	domainsIterator := domainsSet.Iterator()
	if domainsIterator != nil {
		for dom := range domainsIterator.C {
			stuff := strings.Split(dom.(string), ":")
			fmt.Print("\r" + message)
			message = message + "Suspicious domain: " + stuff[0] + " (score:" + stuff[1] + ")\n"
		}
	}
	chatID, _ := strconv.ParseInt(os.Getenv("TG_CHAT"), 10, 64)
	msg := tgbotapi.NewMessage(chatID, message)
	bot.Send(msg)
}
