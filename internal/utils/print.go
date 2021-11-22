package utils

import "github.com/fatih/color"

func PrintOutputCritical(output string) {
	color.Red("[HIGH] - " + output)
}

func PrintOutputMedium(output string) {
	color.Yellow("[MEDIUM] - " + output)
}

func PrintOutputLow(output string) {
	color.Green("[LOW] - " + output)
}
