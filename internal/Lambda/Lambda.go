package lambda

import (
	iam "AWS-audit/internal/iam"
	iamPolicy "AWS-audit/internal/iam/policy"
	utils "AWS-audit/internal/utils"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
)

func Audit() {

	lambdaToAudit := utils.GetServicesToAudit()

	if lambdaToAudit.Lambda == nil {
		utils.PrintInfo("No Lambda configuration found")
		return
	}

	// Create a new session in the us-west-2 region
	sess := session.Must(session.NewSession())

	// map arn -> lambda configuration
	lambdaConfigurations := make(map[string]*lambda.FunctionConfiguration)

	// if wildcard is preset all buckets in the account are audited
	if utils.CheckWildCardInStringArray(lambdaToAudit.Lambda) {
		functions := listLambdasConfiguration(sess)
		if len(functions) == 0 {
			utils.PrintInfo("No Lambda functions found")
			return
		}
		// Updating ARN target to audit
		for _, function := range functions {
			lambdaToAudit.Lambda = append(lambdaToAudit.Lambda, aws.StringValue(function.FunctionArn))
			lambdaConfigurations[aws.StringValue(function.FunctionArn)] = function
		}
	} else { // if no wildcard is preset only the specified buckets are audited
		for _, arn := range lambdaToAudit.Lambda {
			function := getLambdaConfiguration(sess, arn)
			if function == nil {
				utils.PrintError("No Lambda function found for " + arn)

			} else {
				lambdaConfigurations[arn] = function
			}
		}
	}

	utils.PrintInfo("Auditing Lambda Functions")

	for arn, functionConfiguration := range lambdaConfigurations {
		//utils.PrintInfo("Auditing Lambda Function Code Signing for " + arn)
		//runLambdaCodeSigningAudit(sess, functionConfiguration)

		//utils.PrintInfo("Auditing Lambda Function Role for " + arn)
		//runLambdaRoleAudit(sess, functionConfiguration)

		utils.PrintInfo("Auditing Lambda Function Resourse Policy for " + arn)
		runLambdaResourcePolicyAudit(sess, functionConfiguration)

	}

	utils.PrintInfo("Auditing Lambda Functions completed")
}

func runLambdaCodeSigningAudit(sess *session.Session, function *lambda.FunctionConfiguration) {

	result, err := getCodeSigningConfig(sess, function)

	if err != nil {
		utils.PrintError("Error getting Code Signing configuration for " + aws.StringValue(function.FunctionArn))
		return
	}

	if !result {
		utils.PrintOutputMedium("Lambda Function " + aws.StringValue(function.FunctionArn) + " does not have Code Signing configuration")
	}
}

func runLambdaRoleAudit(sess *session.Session, function *lambda.FunctionConfiguration) {

	role := aws.StringValue(function.Role)

	if role == "" {
		utils.PrintError("Lambda Function " + aws.StringValue(function.FunctionArn) + " does not have a role")
		return
	}

	roleName := utils.GetRoleNameFromARN(role)

	rolePolicies, err := iam.ListAttachedAndInlinePolicyFromRole(sess, roleName)

	if err != nil {
		utils.PrintError("Error getting attached and inline policies for " + aws.StringValue(function.FunctionArn))
		return
	}

	fmt.Println(rolePolicies)
}

func runLambdaResourcePolicyAudit(sess *session.Session, function *lambda.FunctionConfiguration) {

	// Get the resource policy for the function
	resourcePolicy, err := getResourcePolicy(sess, aws.StringValue(function.FunctionArn))

	if err != nil {
		return
	}

	iamPolicy.RunPolicyAudit("Lambda Resource Policy", aws.StringValue(function.FunctionArn), *resourcePolicy)

}
