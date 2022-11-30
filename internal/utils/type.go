package utils

type Audit struct {
	S3        Buckets `yaml:"s3"`
	Lambda    Lambdas `yaml:"lambda"`
	Role      Roles   `yaml:"role"`
	AccountId string  `yaml:"account_id"`
	Profile   string  `default:"default" yaml:"profile"`
}

type Buckets []string
type Lambdas []string
type Roles []string

var audit *Audit

func SetAudit(auditToSet *Audit) {
	audit = auditToSet
}

func GetServicesToAudit() *Audit {
	return audit
}
