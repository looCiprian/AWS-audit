package vuln

import (
	"fmt"
	"strconv"
)

var myVulnerabilities vulnerabilities

func addVulnerability(newVulnerability vulnerability) {

	myVulnerabilities.Vuln = append(myVulnerabilities.Vuln, newVulnerability)

}

func NewVulnerability(name VulnerabilityNameValue, description string, service VulnerabilityServiceValue, resourceName string, severity VulnerabilitySeverityValue) {

	myNewVulnerability := vulnerability{}
	myNewVulnerability.ID = len(myVulnerabilities.Vuln)
	myNewVulnerability.Name = name
	myNewVulnerability.Description = description
	myNewVulnerability.Service = service
	myNewVulnerability.ResourceName = resourceName
	myNewVulnerability.Severity = severity
	myNewVulnerability.Remediation = remediations[name]

	addVulnerability(myNewVulnerability)

}

func PrintVulnerabilities() {

	for _, myVulnerability := range myVulnerabilities.Vuln {
		fmt.Println("------------------#" + strconv.Itoa(myVulnerability.ID) + "----------------------------")
		fmt.Print("Name: ")
		fmt.Println(myVulnerability.Name)
		fmt.Print("Description: ")
		fmt.Println(myVulnerability.Description)
		fmt.Print("Service: ")
		fmt.Println(myVulnerability.Service)
		fmt.Print("ResourceName: ")
		fmt.Println(myVulnerability.ResourceName)
		fmt.Print("Severity: ")
		fmt.Println(myVulnerability.Severity.getSeverityString())
		fmt.Print("CVSS Score: ")
		fmt.Println(myVulnerability.CvssScore)
		fmt.Print("CVSS Vector: ")
		fmt.Println(myVulnerability.CvssVector)
		fmt.Print("Remediation: ")
		fmt.Println(myVulnerability.Remediation)
		fmt.Println("----------------------------------------------------")

	}

}
