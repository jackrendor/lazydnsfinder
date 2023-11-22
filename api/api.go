package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackrendor/lazydnsfinder/config"
	"github.com/tidwall/gjson"
)

var Client http.Client

func Init() {

}

type CRTSHData struct {
	IssuerCaId     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	Id             int    `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
}

func CRTSH(domainArg string) []string {
	var jsonData []CRTSHData
	tmp := make(map[string]bool)
	var result []string

	req, reqErr := http.NewRequest("GET", "https://crt.sh/?output=json&q="+domainArg, nil)
	if reqErr != nil {
		log.Println("[CRTSH]", reqErr.Error())
		return nil
	}

	fmt.Println("[CRTSH] interrogating...")
	resp, respErr := Client.Do(req)
	if respErr != nil {
		log.Println("[CRTSH]", respErr.Error())
		return nil
	}

	defer resp.Body.Close()
	if jsonErr := json.NewDecoder(resp.Body).Decode(&jsonData); jsonErr != nil {
		log.Println("[CRTSH]", jsonErr.Error())
		return nil
	}
	for _, node := range jsonData {
		tmp[node.CommonName] = true
		tmp[node.NameValue] = true
	}

	for domain := range tmp {
		result = append(result, domain)
	}
	return result
}

func HackerTarget(domainArg string) []string {
	var result []string

	req, reqErr := http.NewRequest("GET", "https://api.hackertarget.com/hostsearch/?q="+domainArg, nil)
	if reqErr != nil {
		log.Println("[HackerTarget]", reqErr.Error())
		return nil
	}
	fmt.Println("[HackerTarget] interrogating...")
	resp, respErr := Client.Do(req)
	if respErr != nil {
		log.Println("[HackerTarget]", respErr.Error())
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Println("[HackerTarget]", resp.Status)
		return nil
	}
	bodyBytes, readAllErr := io.ReadAll(resp.Body)

	if readAllErr != nil {
		log.Println("[HackerTarget]", readAllErr.Error())
		return nil
	}
	lines := strings.Split(string(bodyBytes), "\n")

	for _, line := range lines {
		result = append(result, strings.Split(line, ",")[0])
	}

	return result

}

func CensysCerts(domainArg string, next string, maxRecursion int) []string {
	var result []string
	if maxRecursion <= 0 {
		return result
	} else {
		maxRecursion--
	}
	req, reqErr := http.NewRequest("GET", "https://search.censys.io/api/v2/certificates/search", nil)
	if reqErr != nil {
		log.Println("[Censys Certs]", reqErr.Error())
		return result
	}
	req.SetBasicAuth(config.Values.Censys.APIID, config.Values.Censys.APISECRET)

	query := req.URL.Query()

	query.Set("q", domainArg)
	query.Set("per_page", "100")
	req.URL.RawQuery = query.Encode()

	if next != "" {
		query.Set("cursor", next)
	}

	fmt.Println("[Censys Certs] interrogating...")
	resp, respErr := Client.Do(req)
	if respErr != nil {
		log.Println("[Censys Certs]", respErr.Error())
		return result
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Println("[Censys Certs]", resp.Status)
		return result
	}

	bodyBytes, readAllErr := io.ReadAll(resp.Body)
	if readAllErr != nil {
		log.Println("[Censys Certs]", respErr.Error())
		return result
	}

	parsedJson := gjson.ParseBytes(bodyBytes)
	if parsedJson.Get("code").Num != 200 {
		log.Println("[Censys Certs]", parsedJson.Get("error"))
		return result
	}

	tmp := make(map[string]bool)
	for _, elem := range parsedJson.Get("result.hits.#.names").Array() {
		for _, nameCert := range elem.Array() {
			if !strings.HasPrefix(nameCert.Str, "*.") {
				tmp[nameCert.Str] = true
			}
		}

	}

	// removes duplicates
	for key := range tmp {
		result = append(result, key)
	}

	nextCursor := parsedJson.Get("links.next").Str
	if nextCursor != "" {
		newdata := CensysCerts(domainArg, nextCursor, maxRecursion)
		result = append(result, newdata...)
	}

	return result
}

func CensysHosts(domainArg string, next string, maxRecursion int) []string {
	var result []string
	if maxRecursion <= 0 {
		return result
	} else {
		maxRecursion--
	}
	req, reqErr := http.NewRequest("GET", "https://search.censys.io/api/v2/hosts/search", nil)
	if reqErr != nil {
		log.Println("[Censys Hosts]", reqErr.Error())
		return result
	}
	req.SetBasicAuth(config.Values.Censys.APIID, config.Values.Censys.APISECRET)

	query := req.URL.Query()
	query.Set("q", domainArg)
	query.Set("per_page", "100")
	query.Set("virtual_hosts", "INCLUDE")
	query.Set("sort", "RELEVANCE")
	if next != "" {
		query.Set("cursor", next)
	}
	req.URL.RawQuery = query.Encode()

	fmt.Println("[Censys Hosts] interrogating...")
	resp, respErr := Client.Do(req)
	if respErr != nil {
		log.Println("[Censys Hosts]", respErr.Error())
		return result
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Println("[Censys Hosts]", resp.Status)
		return result
	}

	bodyBytes, readAllErr := io.ReadAll(resp.Body)
	if readAllErr != nil {
		log.Println("[Censys]", respErr.Error())
		return result
	}

	parsedJson := gjson.ParseBytes(bodyBytes)
	if parsedJson.Get("code").Num != 200 {
		log.Println("[Censys Hosts]", parsedJson.Get("error"))
		return result
	}

	tmp := make(map[string]bool)
	for _, elem := range parsedJson.Get("result.hits.#.name").Array() {
		tmp[elem.Str] = true

	}
	// removes duplicates
	for key := range tmp {
		result = append(result, key)
	}

	nextCursor := parsedJson.Get("links.next").Str
	if nextCursor != "" {
		newdata := CensysHosts(domainArg, nextCursor, maxRecursion)
		result = append(result, newdata...)
	}

	return result
}

func Shodan(domainArg string, next int, maxRecursion int) []string {
	var result []string
	next++
	if maxRecursion <= 0 {
		return result
	} else {
		maxRecursion--
	}
	req, reqErr := http.NewRequest("GET", "https://api.shodan.io/dns/domain/"+domainArg, nil)
	if reqErr != nil {
		log.Println("[Shodan]", reqErr.Error())
		return result
	}

	query := req.URL.Query()
	query.Set("key", config.Values.Shodan.APIKEY)
	query.Set("page", strconv.Itoa(next))

	req.URL.RawQuery = query.Encode()

	fmt.Println("[Shodan] interrogating...")
	resp, respErr := Client.Do(req)
	if respErr != nil {
		log.Println("[Shodan]", respErr.Error())
		return result
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Println("[Shodan]", resp.Status)
		return result
	}

	bodyBytes, readAllErr := io.ReadAll(resp.Body)
	if readAllErr != nil {
		log.Println("[Shodan]", respErr.Error())
		return result
	}

	parsedJson := gjson.ParseBytes(bodyBytes)

	tmp := make(map[string]bool)
	for _, elem := range parsedJson.Get("subdomains").Array() {
		tmp[elem.Str+"."+domainArg] = true

	}
	// removes duplicates
	for key := range tmp {
		result = append(result, key)
	}

	if parsedJson.Get("more").Bool() {
		newdata := Shodan(domainArg, next, maxRecursion)
		result = append(result, newdata...)
	}
	return result
}
