package lambda

import (
	utils "AWS-audit/internal/utils"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
)

// list lambda function in the account and return the arns
func listLambdasConfiguration(sess *session.Session) []*lambda.FunctionConfiguration {

	var arns []*lambda.FunctionConfiguration

	// get all lambda functions in all regions
	for _, region := range utils.Regions {

		svc := lambda.New(sess, &aws.Config{Region: aws.String(region)})

		listConfiguration := &lambda.ListFunctionsInput{}

		for {

			resp, err := svc.ListFunctions(listConfiguration)

			if err != nil {
				utils.PrintError(fmt.Sprintf("Unable to list lambdas, %v.", err))
				break
			}

			for _, function := range resp.Functions {
				arns = append(arns, function)
			}

			// check if there are more results
			if resp.NextMarker == nil {
				break
			} else {
				listConfiguration.Marker = resp.NextMarker
			}
		}
	}

	return arns
}

func getLambdaConfiguration(sess *session.Session, arn string) *lambda.FunctionConfiguration {

	region := utils.GetRegionFromARN(arn)
	if region == "" {
		utils.PrintError(fmt.Sprintf("Unable to get region from ARN %s", arn))
		return nil
	}

	svc := lambda.New(sess, &aws.Config{Region: aws.String(region)})

	getConfiguration := &lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(arn),
	}

	resp, err := svc.GetFunctionConfiguration(getConfiguration)

	if err != nil {
		utils.PrintError(fmt.Sprintf("Unable to get lambda configuration, %v.", err))
		return nil
	}

	return resp
}

// return true if the lambda has code signing configuration
func getCodeSigningConfig(sess *session.Session, configuration *lambda.FunctionConfiguration) (bool, error) {

	arn := aws.StringValue(configuration.FunctionArn)
	region := utils.GetRegionFromARN(arn)

	if region == "" {
		utils.PrintError(fmt.Sprintf("Unable to get region from ARN %s", arn))
		return false, errors.New("unable to get region from ARN")
	}

	svc := lambda.New(sess, &aws.Config{Region: aws.String(region)})

	getCodeSigningConfig := &lambda.GetFunctionCodeSigningConfigInput{
		FunctionName: aws.String(arn),
	}

	resp, err := svc.GetFunctionCodeSigningConfig(getCodeSigningConfig)

	if err != nil {
		return false, err
	}

	if resp.CodeSigningConfigArn == nil {
		return false, err
	}

	return true, nil
}

func getResourcePolicy(sess *session.Session, arn string) (*utils.PolicyDocument, error) {

	region := utils.GetRegionFromARN(arn)
	if region == "" {
		utils.PrintError(fmt.Sprintf("Unable to get region from ARN %s", arn))
		return nil, errors.New("unable to get region from ARN")
	}

	svc := lambda.New(sess, &aws.Config{Region: aws.String(region)})

	getResourcePolicy := &lambda.GetPolicyInput{
		FunctionName: aws.String(arn),
	}

	resp, err := svc.GetPolicy(getResourcePolicy)

	if err != nil {
		return nil, err
	}

	var resourcePolicy utils.PolicyDocument

	err = json.Unmarshal([]byte(aws.StringValue(resp.Policy)), &resourcePolicy)
	if err != nil {
		utils.PrintError(fmt.Sprintf("Unable to parse policy, %v.", err))
		return nil, err
	}

	return &resourcePolicy, nil
}

// return map of lambda function environment variables from session and function arn
func getEnvironmentVariables(sess *session.Session, arn string) (map[string]string, error) {

	result := make(map[string]string)

	region := utils.GetRegionFromARN(arn)
	if region == "" {
		utils.PrintError(fmt.Sprintf("Unable to get region from ARN %s", arn))
		return result, errors.New("unable to get region from ARN")
	}

	svc := lambda.New(sess, &aws.Config{Region: aws.String(region)})

	configurationInput := &lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(arn),
	}

	configuration, err := svc.GetFunctionConfiguration(configurationInput)

	if err != nil {
		return result, err
	}

	if configuration.Environment == nil {
		return result, nil
	}

	variables := configuration.Environment.Variables

	for key, value := range variables {
		result[key] = aws.StringValue(value)
	}

	return result, nil

}
