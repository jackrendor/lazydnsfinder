package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/jackrendor/lazydnsfinder/api"
	"github.com/jackrendor/lazydnsfinder/utilsdns"

	"github.com/likexian/whois"
)

func main() {
	domain := flag.String("domain", "", "Domain to find subdomains from")
	noWhois := flag.Bool("nowhois", false, "Just list possible subdomains without performing whois on IPs")
	flag.Parse()
	if len(*domain) == 0 {
		flag.Usage()
		return
	}

	var allDomains []string
	allDomains = api.CRTSH(*domain)
	allDomains = append(allDomains, api.HackerTarget(*domain)...)

	allDomains = utilsdns.RemoveDuplicateStr(allDomains)
	for _, element := range allDomains {

		domainWhois, domainWhoisErr := whois.Whois(element)

		if domainWhoisErr != nil {
			fmt.Printf("\n%s\n", element)
		} else {
			fmt.Printf("\n%s [%s]\n", element, utilsdns.GetValueFromWhois(domainWhois, "registrar"))
		}
		if *noWhois {
			continue
		}
		ips, ipsEr := net.LookupIP(element)
		if ipsEr == nil {
			for _, ip := range ips {
				whoisRaw, whoisErr := whois.Whois(ip.String())
				if whoisErr != nil {
					fmt.Println(" [No info]", ip.String())
				} else {
					registrar := utilsdns.GetValueFromWhois(whoisRaw, "org-name")
					//descr or org-name
					if registrar == "No info" {
						registrar = utilsdns.GetValueFromWhois(whoisRaw, "descr")
					}
					fmt.Printf(" %s [%s] %s\n", utilsdns.GetValueFromWhois(whoisRaw, "country"), registrar, ip.String())
				}

			}
		}
	}
}
