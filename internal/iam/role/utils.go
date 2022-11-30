package role

import (
	iamInternal "AWS-audit/internal/iam"
	"AWS-audit/internal/utils"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

func getRolePolicy(sess *session.Session, roleName string) map[string]*utils.PolicyDocument {

	service := iam.New(sess)
	attachedPoliciesList, err := service.ListAttachedRolePolicies(
		&iam.ListAttachedRolePoliciesInput{
			RoleName: aws.String(roleName),
		})

	if err != nil {
		utils.PrintInfo(fmt.Sprintf("No attached policies found for role %s", roleName))
	}

	policiesList, err := service.ListRolePolicies(&iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	})

	if err != nil {
		utils.PrintInfo(fmt.Sprintf("No inline policies found for role %s", roleName))
	}

	policiesDocuments := make(map[string]*utils.PolicyDocument)

	for _, attachePName := range attachedPoliciesList.AttachedPolicies {

		policyDocument, err := iamInternal.GetAttachedPolicyDocumentFromPolicyArn(sess, aws.StringValue(attachePName.PolicyArn))
		if err == nil {
			policiesDocuments[aws.StringValue(attachePName.PolicyName)] = policyDocument
		}

	}

	for _, PName := range policiesList.PolicyNames {

		policyDocument, err := iamInternal.GetInlinePolicyDocumentFromRoleAndPolicyName(sess, roleName, aws.StringValue(PName))
		if err == nil {
			policiesDocuments[aws.StringValue(PName)] = policyDocument
		}

	}

	return policiesDocuments

}
