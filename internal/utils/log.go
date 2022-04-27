package utils

import "log"

func PrintError(err string) {
	log.Println("[ERROR] " + err)
}

func PrintWarning(err string) {
	log.Println("[WARNING] " + err)
}

func PrintInfo(err string) {
	log.Println("[INFO] " + err)
}
