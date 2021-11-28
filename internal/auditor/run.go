package auditor

import (
	"AWS-audit/internal/lambda"
	"AWS-audit/internal/s3"
	utils "AWS-audit/internal/utils"
)

func Run(servicesToAudit *utils.Audit) {

	s3.Audit(servicesToAudit)
	lambda.Audit(servicesToAudit)

}
