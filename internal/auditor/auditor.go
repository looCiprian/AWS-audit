package auditor

import (
	utils "AWS-audit/internal/utils"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
)

func AuditorImporter(file string) *utils.Audit {

	if !FileExists(file) {
		utils.PrintError("File does not exist")
		return nil
	}

	if ReadFile(file) == "" {
		utils.PrintError("File is empty")
		return nil
	}

	var audit utils.Audit
	err := yaml.Unmarshal([]byte(ReadFile(file)), &audit)
	if err != nil {
		utils.PrintError(err.Error())
		return nil
	}

	return &audit

}

// check if file exists
func FileExists(file string) bool {
	if _, err := os.Stat(file); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// return content of a file
func ReadFile(file string) string {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		return ""
	}
	return string(content)
}
