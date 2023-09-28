package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
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
	resp, respErr := Client.Do(req)
	if respErr != nil {
		log.Println("[HackerTarget]", respErr.Error())
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Println("[HackerTarget]", respErr.Error())
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
