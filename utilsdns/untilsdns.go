package utilsdns

import (
	"strings"
)

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
