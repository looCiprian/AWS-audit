package utils

type Audit struct {
	S3        Buckets `yaml:"s3"`
	Lambda    Lambdas `yaml:"lambda"`
	AccountId string  `yaml:"account_id"`
}

type Buckets []string
type Lambdas []string

var audit *Audit

func SetAudit(auditToSet *Audit) {
	audit = auditToSet
}

func GetServicesToAudit() *Audit {
	return audit
}
