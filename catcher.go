package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/CaliDog/certstream-go"
	"github.com/deckarep/golang-set"
	"github.com/joeguo/tldextract"
	"github.com/texttheater/golang-levenshtein/levenshtein"
)

type Source struct {
	Domains []string
	TLDs    []string
}

func main() {
	//load TLD file
	cache := "/tmp/tld.cache"
	extract, _ := tldextract.New(cache, false)

	var source Source
	//loading file
	if _, err := toml.DecodeFile("config.toml", &source); err != nil {
		fmt.Println("Unable to read config file")
		os.Exit(1)
	}
	fmt.Println("[+] Starting scraping")
	stream, errStream := certstream.CertStreamEventStream(true)
	i := 0
	for {
		select {
		case jq := <-stream:
			i += 1
			fmt.Printf("\rCertificates: %d", i)
			domains, err := jq.ArrayOfStrings("data", "leaf_cert", "all_domains")
			if err != nil {
				panic(err)
			}
			domainsSet := mapset.NewSet()
			for _, domain := range domains {
				parseDomain(domain, source, extract, domainsSet)
			}
			if domainsSet.Cardinality() > 0 {
				go sendTelegramNotify(domainsSet)
			}

		case err := <-errStream:
			panic(err)
		}
	}
}

func parseDomain(domain string, source Source, extract *tldextract.TLDExtract, domainsSet mapset.Set) {
	suspectFlag := false
	score := 0
	// remember the initial domain
	startDomain := domain
	//remove wildcards
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimPrefix(domain, "www.")
	domain = strings.TrimPrefix(domain, "ww3.")
	// remove TLD
	breakDomain := extract.Extract(domain)
	// check if strange the domain has suspect TLDs
	for _, TLD := range source.TLDs {
		if breakDomain.Tld == TLD {
			score += 20
		}
	}
	domain = (breakDomain.Sub + "." + breakDomain.Root)

	if len(domain) <= 17 {
		score -= 20
	}
	//disassemble subdomains
	words := strings.Split(domain, ".")
	//multiple subdomains = probably phishing
	if len(words) > 3 {
		score += (3 * len(words))
	} else if len(words) == 1 {
		score -= 10
	}

	checkTLDandDomains(words, source.Domains, &score, &suspectFlag)
	if score > 60 && suspectFlag {
		domainsSet.Add(startDomain + ":" + strconv.Itoa(score))
	}

}

func checkTLDandDomains(words []string, legitDomains []string, score *int, suspectFlag *bool) {
	for wordCounter, word := range words {
		// count nuber of - in the word
		if strings.Count(word, "-") >= 3 {
			*score += strings.Count(word, "-") * 3
		}
		// check the lenght of each word
		if len(word) >= 40 {
			*score += 1 * (len(word) - 40)
		}
		//if removed the TLD still has another TLD something bad is going on
		if word == "com" || word == "it" || word == "org" || word == "net" || word == "us" {
			*score += 40
		}

		//false positive
		if word == "cloud" || word == "mail" || word == "email" {
			continue
		}
		if strings.Contains(word, "com-") || strings.Contains(word, "us-") || strings.Contains(word, "net-") {
			*score += 40
		}

		for _, legitDomain := range legitDomains {
			//check if is the same
			if word == legitDomain {
				*score += 70
				*suspectFlag = true
			} else if strings.Contains(word, legitDomain) {
				*score += 40
				//-apple-
				if strings.Contains(word, "-"+legitDomain) || strings.Contains(word, legitDomain+"-") {
					*score += 20
				}
				// higher penality if the word is the first or the second
				if wordCounter == 0 || wordCounter == 1 {
					*score += 20
				}
				*suspectFlag = true
			}
			//Levenshtein distance
			checkDistance(word, legitDomain, score, suspectFlag)
		}
	}
}

func checkDistance(domain string, legitDomain string, score *int, suspectFlag *bool) {
	if len(domain) > 3 {
		distance := levenshtein.DistanceForStrings([]rune(legitDomain), []rune(domain), levenshtein.DefaultOptions)
		if distance == 1 {
			*score += 70
			*suspectFlag = true
		}
	}
}
