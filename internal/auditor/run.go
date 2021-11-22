package auditor

import (
	"AWS-audit/internal/S3"
	utils "AWS-audit/internal/utils"
)

func Run(servicesToAudit *utils.Audit) {

	S3.Audit(servicesToAudit)

}
