package role

import (
	"AWS-audit/internal/utils"

	"github.com/aws/aws-sdk-go/aws/session"
)

func Audit() {

	roleToAudit := utils.GetServicesToAudit()

	if roleToAudit.Role == nil {
		utils.PrintInfo("No role found")
		return
	}

	sess := session.Must(session.NewSessionWithOptions(session.Options{Profile: roleToAudit.Profile}))

	for _, role := range roleToAudit.Role {

		roleName := utils.GetRoleNameFromARN(role)
		getRolePolicy(sess, roleName)

	}

}

func RunRoleAudit(arn string) {

}
