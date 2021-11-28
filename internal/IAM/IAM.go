package iam

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

// function to list attached and inline policies to a user, return policies names
func ListAttachedAndInlinePolicyFromRole(sess *session.Session, roleName string) ([]string, error) {

	policiesAttached, err := listAttachedPolicyFromRole(sess, roleName)
	policiesInline, err1 := listInlinePolicyFromRole(sess, roleName)

	if err != nil || err1 != nil {
		return nil, err
	}

	policies := append(policiesAttached, policiesInline...)
	return policies, nil
}

// function to list attached and inline policies to a role, return policies names
func listAttachedPolicyFromRole(sess *session.Session, roleName string) ([]string, error) {

	var policies []string

	svc := iam.New(sess)
	params := &iam.ListAttachedRolePoliciesInput{
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
func listInlinePolicyFromRole(sess *session.Session, roleName string) ([]string, error) {

	var policies []string

	svc := iam.New(sess)
	params := &iam.ListRolePoliciesInput{
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
