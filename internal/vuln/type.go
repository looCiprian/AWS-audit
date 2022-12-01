package vuln

type vulnerabilities struct {
	Vuln []vulnerability
}

type vulnerability struct {
	ID           int                        // The unique ID of the vulnerability
	Name         VulnerabilityNameValue     // The name of the vulnerability
	Description  string                     // The description of the vulnerability
	Service      VulnerabilityServiceValue  // The service affected by the vulnerability
	ResourceName string                     // The resource ARN affected by the vulnerability
	Severity     VulnerabilitySeverityValue // The severity of the vulnerability
	CvssScore    float32                    // The CVSS score of the vulnerability
	CvssVector   string                     // The CVSS vector of the vulnerability
	Remediation  string                     // The remediation of the vulnerability
}

// Service Name
type VulnerabilityServiceValue string

const (
	AmazonS3     = "Amazon S3"
	AmazonLambda = "Amazon Lambda"
	AmazonIAM    = "Amazon IAM"
)

// SeverityValue is the severity of the vulnerability
type VulnerabilitySeverityValue int

const (
	SeverityInfo VulnerabilitySeverityValue = iota
	// SeverityLow is the severity of the vulnerability
	SeverityLow
	// SeverityMedium is the severity of the vulnerability
	SeverityMedium
	// SeverityHigh is the severity of the vulnerability
	SeverityHigh
)

// Vulnerability Names
type VulnerabilityNameValue string

const (
	S3ACLPublic                VulnerabilityNameValue = "Amazon S3 Bucket ACL allow public access"
	S3Versioning               VulnerabilityNameValue = "Amazon S3 Bucket versioning not enabled"
	S3Encryption               VulnerabilityNameValue = "Amazon S3 Bucket encryption not enabled"
	S3Logging                  VulnerabilityNameValue = "Amazon S3 Bucket logging not enabled"
	S3Website                  VulnerabilityNameValue = "Amazon S3 Bucket website enabled"
	S3BlockPublicAccess        VulnerabilityNameValue = "Amazon S3 Bucket doest not block public access"
	S3DeleteMFA                VulnerabilityNameValue = "Amazon S3 Bucket MFA delete not enabled"
	S3HTTPAccess               VulnerabilityNameValue = "Amazon S3 Bucket allows HTTP access"
	IAMInfo                    VulnerabilityNameValue = "IAM configuration must be also validated manually"
	IAMPolicyWildCardPrincipal VulnerabilityNameValue = "IAM principal allow *"
	IAMPolicyWildCardAction    VulnerabilityNameValue = "IAM policy action allow *"
	IAMPolicyWildCardResource  VulnerabilityNameValue = "IAM policy resource allow *"
	IAMPolicyCrossAccount      VulnerabilityNameValue = "IAM policy allow cross account access"
	LambdaCodeSigning          VulnerabilityNameValue = "Lambda function code signing not enabled"
	LambdaEnvVariables         VulnerabilityNameValue = "Lambda function has environment variables"
	RoleNotUsed                VulnerabilityNameValue = "Role has neverd used in the last 400 days"
)

// Remediations
var remediations = map[VulnerabilityNameValue]string{
	S3ACLPublic:                "Ensure that the bucket ACL not allows public access",
	S3Versioning:               "Ensure that the bucket versioning is enabled",
	S3Encryption:               "Ensure that the bucket encryption is enabled",
	S3Logging:                  "Ensure that the bucket logging is enabled",
	S3Website:                  "Ensure that the bucket website is disabled",
	S3BlockPublicAccess:        "Ensure that the bucket block public access is enabled",
	S3DeleteMFA:                "Ensure that the bucket MFA delete is enabled",
	S3HTTPAccess:               "Ensure that the bucket HTTP access is disabled",
	IAMInfo:                    "Ensure that the IAM configuration is also validated manually",
	IAMPolicyWildCardPrincipal: "Ensure that the principal is not *",
	IAMPolicyWildCardAction:    "Ensure that the action is not *",
	IAMPolicyWildCardResource:  "Ensure that the resource is not *",
	IAMPolicyCrossAccount:      "Ensure that the policy does not allow cross account access",
	LambdaCodeSigning:          "Ensure that the lambda function code signing is enabled",
	LambdaEnvVariables:         "Ensure that the lambda function does not contain sensitive data or database credentials",
	RoleNotUsed:                "Remove unused role",
}
