package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/CaliDog/certstream-go"
	"github.com/deckarep/golang-set"
	"github.com/joeguo/tldextract"
)

type Domain struct {
	Name          string
	badTLD        bool
	similarity    float32
	multipleTLD   bool
	lenght        int
	numberOfDash  int
	subdomain     int
	falsePositive bool
	fakedTLD      bool
	fakeSuffix    bool
	buzzwords     bool
}

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
	fmt.Println("[+] Scraping")
	fmt.Println("Domain, similarity, lenght, badTLD, fakedTLD, fake suffix, multipleTLD, buzzwords, number of dashes, number of subdomains, falsePositive")
	stream, errStream := certstream.CertStreamEventStream(true)
	if len(os.Args) >= 2 {
		domainsSet := mapset.NewSet()
		for k, arg := range os.Args {
			if k > 0 {
				fmt.Println(arg)
				parseDomain(arg, source, extract, domainsSet)
			}
		}
		os.Exit(1)
	}
	for {
		select {
		case jq := <-stream:
			domains, err := jq.ArrayOfStrings("data", "leaf_cert", "all_domains")
			if err != nil {
				panic(err)
			}
			domainsSet := mapset.NewSet()
			for _, domain := range domains {
				parseDomain(domain, source, extract, domainsSet)
			}

		case err := <-errStream:
			panic(err)
		}
	}
}

func parseDomain(domain string, source Source, extract *tldextract.TLDExtract, domainsSet mapset.Set) {
	dom := new(Domain)
	dom.Name = domain
	dom.numberOfDash = strings.Count(domain, "-")
	//remove wildcards
	wildcards := [3]string{"*.", "www", "www3."}
	for _, wc := range wildcards {
		domain = strings.TrimPrefix(domain, wc)
	}

	//remove false positives
	falsePositives := [5]string{"webmail.", "mail.", "ftp.", "cloud.", "email."}
	for _, fp := range falsePositives {
		domain2 := strings.TrimPrefix(domain, fp)
		if domain != domain2 {
			dom.falsePositive = true
			domain = domain2
		}
	}
	// remove TLD
	breakDomain := extract.Extract(domain)
	// check if strange the domain has suspect TLDs
	for _, TLD := range source.TLDs {
		if breakDomain.Tld == TLD {
			dom.badTLD = true
		}
	}

	// check if the domain is legit, otherwise calculate the distance
	for _, legitDomain := range source.Domains {
		//this is so ugly
		if breakDomain.Root == legitDomain && (breakDomain.Tld == "it" || breakDomain.Tld == "com" || breakDomain.Tld == "org" || breakDomain.Tld == "net" || breakDomain.Tld == "co.uk") {
			return
		} else { // check distance
			distance := checkDistance(domain, legitDomain, dom)
			//save only the higher value
			if distance > dom.similarity {
				dom.similarity = distance
			}
		}
	}
	domain = (breakDomain.Sub + "." + breakDomain.Root)
	dom.lenght = len(domain)

	//check for buzzwords
	buzzwords := []string{"signin", "secure", "signup", "login", "userid", "verify", "download", "confirm", "account", "auth"}
	for _, bw := range buzzwords {
		if strings.Contains(domain, bw) {
			dom.buzzwords = true
		}
	}
	//disassemble subdomains
	words := strings.Split(domain, ".")
	//removing possible whitespace at the start of the line
	if words[0] == "" {
		words = append(words[:0], words[1:]...)
	}
	//multiple subdomains = probably phishing
	dom.subdomain = len(words)
	checkTLDandDomains(words, source.Domains, dom)
	//printing domain data
	fmt.Println(dom.Name, dom.similarity, dom.lenght, dom.badTLD, dom.fakedTLD, dom.fakeSuffix, dom.multipleTLD, dom.buzzwords, dom.numberOfDash, dom.subdomain, dom.falsePositive)
}

func checkTLDandDomains(words []string, legitDomains []string, dom *Domain) {
	for _, word := range words {
		//if removed the TLD still has another TLD something bad is going on
		goodTLDs := []string{"com", "it", "org", "net", "us"}
		for _, gt := range goodTLDs {
			if word == gt {
				dom.multipleTLD = true
			}
		}
		//check for fake TLDS apple.com-totallyphishing.com
		fakeTLDs := []string{"com-", "us-", "net-"}
		for _, ft := range fakeTLDs {
			if strings.Contains(word, ft) {
				dom.fakedTLD = true
			}
		}
		//check for fake suffix apple-appleid-com.foo
		fakeSuffix := []string{"-us", "-com", "-net", "-it", "-org"}
		for _, fs := range fakeSuffix {
			if strings.HasSuffix(word, fs) {
				dom.fakeSuffix = true
			}
		}
	}
}

func checkDistance(domain string, legitDomain string, dom *Domain) float32 {
	distance := calcSimilarity(legitDomain, domain, 0.7)
	return distance
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func max(x, y int) int {
	if x > y {
		return x
	}
	return y
}

func maxf(x, y float32) float32 {
	if x > y {
		return x
	}
	return y
}

func compute_magic_vector(a string, b string) []int {
	na := len(a)
	nb := len(b)
	ih := make([][]int, 2)
	ih[0] = make([]int, nb+1)
	ih[1] = make([]int, nb+1)
	iv := make([][]int, 2)
	iv[0] = make([]int, nb+1)
	iv[1] = make([]int, nb+1)

	for j := 0; j <= nb; j++ {
		ih[0][j] = j
	}

	for l := 1; l <= na; l++ {
		iv[1][0] = 0
		for j := 1; j <= nb; j++ {
			if a[l-1] != b[j-1] {
				ih[1][j] = max(iv[1][j-1], ih[0][j])
				iv[1][j] = min(iv[1][j-1], ih[0][j])
			} else {
				ih[1][j] = iv[1][j-1]
				iv[1][j] = ih[0][j]
			}
		}
		iv[1], iv[0] = iv[0], iv[1]
		ih[1], ih[0] = ih[0], ih[1]
	}
	return ih[0]
}

//this is magic :)
func calcSimilarity(a string, b string, tsh float32) float32 {
	v := compute_magic_vector(a, b)
	bound := int(float32(len(a)) / tsh)
	na := len(a)
	nb := len(b)
	var best float32

	for i := 0; i <= nb; i++ {
		var br float32
		cij := 0

		for j := i + 1; j <= nb && j <= i+bound; j++ {
			if v[j] <= i {
				cij++
			}

			var cur = float32(cij)/float32(max(j-i, na)) - float32(min(i, nb-j))*0.1
			if cur > br {
				br = cur
			}
		}

		if br >= best {
			best = br
		}
	}

	return best
}
