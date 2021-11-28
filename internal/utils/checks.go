package utils

import (
	"strings"
)

// check if * is in the array
func CheckWildCardInStringArray(s []string) bool {
	for _, a := range s {
		if a == "*" {
			return true
		}
	}
	return false
}

// check if string contains *
func CheckWildCardInString(statement string) bool {
	return strings.Contains(statement, "*")
}

func GetAccountId() string {
	services := GetServicesToAudit()

	if services == nil {
		return ""
	}

	return services.AccountId

}
