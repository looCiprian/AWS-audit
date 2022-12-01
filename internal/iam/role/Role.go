package role

import (
	"AWS-audit/internal/iam/policy"
	"AWS-audit/internal/utils"
	"AWS-audit/internal/vuln"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

func Audit() {

	roleToAudit := utils.GetServicesToAudit()

	if roleToAudit.Role == nil {
		utils.PrintInfo("No role found")
		return
	}

	sess := session.Must(session.NewSessionWithOptions(session.Options{Profile: roleToAudit.Profile}))

	for _, role := range roleToAudit.Role {
		utils.PrintInfo(fmt.Sprintf("Assessing role %s", role))
		runRolePolicyAudit(sess, role)
		runRoleLastUse(sess, role)
	}

}

func runRolePolicyAudit(sess *session.Session, arn string) {

	roleName := utils.GetRoleNameFromARN(arn)
	policyDocuments := getRolePolicy(sess, roleName)

	for policyName, policyDocument := range policyDocuments {

		policy.RunPolicyAudit("Role "+arn+" policy: ", policyName, *policyDocument)

	}
}

func runRoleLastUse(sess *session.Session, arn string) {

	iamSess := iam.New(sess)
	roleName := utils.GetRoleNameFromARN(arn)

	roleOutput, err := iamSess.GetRole(&iam.GetRoleInput{RoleName: aws.String(roleName)})

	if err != nil {
		utils.PrintError(fmt.Sprintf("Cannot get role detail for role: %s", roleName))
	}

	if roleOutput.Role.RoleLastUsed.LastUsedDate == nil {
		description := fmt.Sprintf("The role %s was not used in the last 400 days", roleName)
		vuln.NewVulnerability(vuln.RoleNotUsed, description, vuln.AmazonIAM, roleName, vuln.SeverityHigh)
	}

}
