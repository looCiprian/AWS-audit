package utils

import "log"

func PrintError(err string){
	log.Fatalln("[ERROR] " + err)
}