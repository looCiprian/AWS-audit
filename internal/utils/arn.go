package utils

import (
	"strings"

	"github.com/gigawattio/awsarn"
)

func GetRegionFromARN(arn string) string {
	component, err := awsarn.Parse(arn)
	if err != nil {
		return ""
	}
	return component.Region
}

func GetRoleNameFromARN(arn string) string {
	component, err := awsarn.Parse(arn)
	if err != nil {
		return ""
	}

	// e.s service-role/test-role-x8v6h8l6
	roleName := strings.Split(component.Resource, "/")[1]

	return roleName
}
