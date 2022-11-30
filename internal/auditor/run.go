package auditor

import (
	"AWS-audit/internal/iam/role"
	"AWS-audit/internal/lambda"
	"AWS-audit/internal/s3"
	utils "AWS-audit/internal/utils"
	"AWS-audit/internal/vuln"
)

func Run(servicesToAudit *utils.Audit) {

	utils.SetAudit(servicesToAudit)

	role.Audit()
	s3.Audit()
	lambda.Audit()

	vuln.PrintVulnerabilities()
}
