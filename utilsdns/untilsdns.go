package utilsdns

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type Data struct {
	CountryCode string `json:"country_code"`
	Connection  struct {
		ASN    int    `json:"asn"`
		Org    string `json:"org"`
		ISP    string `json:"isp"`
		Domain string `json:"domain"`
	} `json:"connection"`
}

func GetDataFromIP(ip string) (Data, error) {
	var data Data
	resp, respErr := http.Get("https://ipwho.is/" + ip + "?fields=connection,country_code")
	if respErr != nil {
		return data, respErr
	}

	// Can't marshal data. Assuming empty response
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return data, errors.New("Empty response")
	}

	return data, nil
}

func GetValueFromWhois(whoisRaw string, value string) string {

	for _, line := range strings.Split(whoisRaw, "\n") {
		tmp := strings.Split(line, ":")
		key := strings.ToLower(tmp[0])
		valueNoDash := strings.ReplaceAll(value, "-", "")
		if key == value || key == valueNoDash {
			return strings.TrimSpace(tmp[1])
		}
	}

	return "No info"
}
func RemoveDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
