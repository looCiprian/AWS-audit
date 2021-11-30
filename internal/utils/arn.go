package utils

import (
	"strings"

	awsArn "github.com/aws/aws-sdk-go/aws/arn"
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

	roleName := ""

	if strings.Contains(component.Resource, "/") {
		// e.s service-role/test-role-x8v6h8l6
		roleName = strings.Split(component.Resource, "/")[1]
	} else {
		roleName = component.Resource
	}

	return roleName
}

func IsArn(arn string) bool {

	return awsArn.IsARN(arn)
}

func GetAccountIdFromARN(arn string) string {
	component, err := awsarn.Parse(arn)
	if err != nil {
		return ""
	}

	return component.AccountID
}
