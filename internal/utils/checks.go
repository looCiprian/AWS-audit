package utils

// check if * is in the array
func CheckWildCard(s []string) bool {
	for _, a := range s {
		if a == "*" {
			return true
		}
	}
	return false
}
