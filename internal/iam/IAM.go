package iam

import (
	"AWS-audit/internal/utils"
	"encoding/json"
	"net/url"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	iamAWS "github.com/aws/aws-sdk-go/service/iam"
)

// function to list attached and inline policies to a user, return policies names
/*func ListAttachedAndInlinePolicyFromRole(sess *session.Session, roleName string) ([]string, error) {

	policiesAttached, err := listAttachedPolicyFromRole(sess, roleName)
	policiesInline, err1 := listInlinePolicyFromRole(sess, roleName)

	if err != nil || err1 != nil {
		return nil, err
	}

	policies := append(policiesAttached, policiesInline...)
	return policies, nil
}*/

// function to list attached and inline policies to a role, return policies names
func ListAttachedPolicyARNFromRole(sess *session.Session, roleName string) ([]string, error) {

	var policies []string

	svc := iamAWS.New(sess)
	params := &iamAWS.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	}

	for {

		resp, err := svc.ListAttachedRolePolicies(params)
		if err != nil {
			return policies, err
		}
		for _, policy := range resp.AttachedPolicies {
			policies = append(policies, aws.StringValue(policy.PolicyArn))
		}
		// check if there are more pages
		if !aws.BoolValue(resp.IsTruncated) {
			break
		}
		params.Marker = resp.Marker
	}

	return policies, nil
}

// function to list inline policies to a role, return policies names
func ListInlinePolicyNamesFromRole(sess *session.Session, roleName string) ([]string, error) {

	var policies []string

	svc := iamAWS.New(sess)
	params := &iamAWS.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	}

	for {

		resp, err := svc.ListRolePolicies(params)
		if err != nil {
			return policies, err
		}
		for _, policy := range resp.PolicyNames {
			policies = append(policies, aws.StringValue(policy))
		}
		// check if there are more pages
		if !aws.BoolValue(resp.IsTruncated) {
			break
		}
		params.Marker = resp.Marker
	}

	return policies, nil
}

func GetInlinePolicyDocumentFromRoleAndPolicyName(sess *session.Session, roleName, policyName string) (*utils.PolicyDocument, error) {

	svc := iamAWS.New(sess)
	params := &iamAWS.GetRolePolicyInput{
		PolicyName: aws.String(policyName),
		RoleName:   aws.String(roleName),
	}

	resp, err := svc.GetRolePolicy(params)
	if err != nil {
		return nil, err
	}

	// decode the policy document
	decodePolicy, err3 := url.QueryUnescape(aws.StringValue(resp.PolicyDocument))

	if err3 != nil {
		return nil, err3
	}

	var policyDocument *utils.PolicyDocument
	err1 := json.Unmarshal([]byte(decodePolicy), &policyDocument)

	if err1 != nil {
		return nil, err
	}

	return policyDocument, nil
}

func GetAttachedPolicyDocumentFromPolicyArn(sess *session.Session, policyArn string) (*utils.PolicyDocument, error) {

	svc := iamAWS.New(sess)

	// get defautl policy version
	params := &iamAWS.GetPolicyInput{
		PolicyArn: aws.String(policyArn),
	}

	resp, err := svc.GetPolicy(params)
	if err != nil {
		return nil, err
	}

	defaultPolicyVersion := aws.StringValue(resp.Policy.DefaultVersionId)

	// get the specific policy version
	params1 := &iamAWS.GetPolicyVersionInput{
		PolicyArn: aws.String(policyArn),
		VersionId: aws.String(defaultPolicyVersion),
	}

	resp1, err1 := svc.GetPolicyVersion(params1)

	if err1 != nil {
		return nil, err1
	}

	// decode the policy document
	decodePolicy, err3 := url.QueryUnescape(aws.StringValue(resp1.PolicyVersion.Document))

	if err3 != nil {
		return nil, err3
	}

	var policyDocument *utils.PolicyDocument
	err2 := json.Unmarshal([]byte(decodePolicy), &policyDocument)

	if err2 != nil {
		return nil, err2
	}

	return policyDocument, nil
}
