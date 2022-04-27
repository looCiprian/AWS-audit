# AWS-audit
Allows to discover AWS misconfiguration and security issues on S3, Lambda Function and IAM Policy attached to those services.


## Services

### S3

- Bucket Policy Audit [principal, resource, action contains *]
- AccessPoint Policy Audit [principal, resource, action contains *]
- ACL Audit
- Public Access Audit
- Encryption Configuration
- Versioning
- Logging
- Web Site Audit functionality
- Bucket Policy doent not prevent HTTP access

### Lambda

- Lambda Code Signing Audit
- Lambda Role (Policy audit) [principal, resource, action contains *]
- Lambda Resource Policy Audit [principal, resource, action contains *]
- Lambda Environment Audit

## How to run
```
go run AWS-audit.go -c aws-audit-example.yaml
```