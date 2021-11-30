package policy

import (
	"AWS-audit/internal/utils"
	"fmt"
)

// TODO: to be implemented if policy will be inserted in the config yaml file
func Audit() {

}

func RunPolicyAudit(serviceName string, service string, policy utils.PolicyDocument) {

	CheckPolicyPrincipal(serviceName, service, policy)
	CheckPolicyAction(serviceName, service, policy)
	CheckPolicyResource(serviceName, service, policy)
	CheckCrossAccountAccess(serviceName, service, policy)

}

// Check Cross Account Access, by looking if policy principal as different account id
func CheckCrossAccountAccess(serviceName string, service string, policy utils.PolicyDocument) {
	for i, statement := range policy.Statements {
		// for each Principal in statement check if it contains *
		utils.PrintInfo("Checking cross account access for " + serviceName + " " + service)
		for _, principals := range statement.Principal {
			for _, principal := range principals {
				result := fmt.Sprintf(serviceName+" %s allow cross account access to %s, actions: %s, effects: %s, resources: %s, conditions: %s", service, principal, policy.Statements[i].Action, policy.Statements[i].Effect, policy.Statements[i].Resource, policy.Statements[i].Condition)
				if utils.IsArn(principal) {
					if utils.GetAccountId() != utils.GetAccountIdFromARN(principal) {
						utils.PrintOutputCritical(result)
					}
				}
			}
		}
	}
}

// audit principal of a policy document
func CheckPolicyPrincipal(serviceName string, service string, policy utils.PolicyDocument) {

	for i, statement := range policy.Statements {
		// for each Principal in statement check if it contains *
		utils.PrintInfo("Checking principal for " + serviceName + " " + service)
		for _, principals := range statement.Principal {
			for _, principal := range principals {
				result := fmt.Sprintf(serviceName+" %s has a principal %s, actions: %s, effects: %s, resources: %s, conditions: %s", service, principal, policy.Statements[i].Action, policy.Statements[i].Effect, policy.Statements[i].Resource, policy.Statements[i].Condition)
				if utils.CheckWildCardInString(principal) && statement.Effect != "Deny" {
					utils.PrintOutputCritical(result)
				} else {
					utils.PrintOutputLow(result)
				}
			}
		}
	}
}

// audit action of a policy document
func CheckPolicyAction(serviceName string, service string, policy utils.PolicyDocument) {

	for i, statement := range policy.Statements {

		utils.PrintInfo("Checking actions for " + serviceName + " " + service)
		// for each Action in statement check if it contains *
		if statement.Action != nil {
			for _, action := range statement.Action {
				result := fmt.Sprintf(serviceName+" %s has an action %s, principal %s, effects: %s, resources %s, conditions: %s", service, action, policy.Statements[i].Principal, policy.Statements[i].Effect, policy.Statements[i].Resource, policy.Statements[i].Condition)
				if utils.CheckWildCardInString(action) && statement.Effect != "Deny" {
					utils.PrintOutputCritical(result)
				} else {
					utils.PrintOutputLow(result)
				}
			}
		}

	}
}

// audit resource of a policy document
func CheckPolicyResource(serviceName string, service string, policy utils.PolicyDocument) {

	for i, statement := range policy.Statements {

		utils.PrintInfo("Checking resources for " + serviceName + " " + service)
		// for each Resource in statement check if it contains *
		if statement.Resource != nil {
			for _, resource := range statement.Resource {
				result := fmt.Sprintf(serviceName+" %s has a resource %s, actions: %s, principal %s, effects: %s, conditions: %s", service, resource, policy.Statements[i].Action, policy.Statements[i].Principal, policy.Statements[i].Effect, policy.Statements[i].Condition)
				if utils.CheckWildCardInString(resource) && statement.Effect != "Deny" {
					utils.PrintOutputCritical(result)
				} else {
					utils.PrintOutputLow(result)
				}
			}
		}

	}
}
