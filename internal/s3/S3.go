package s3

import (
	"encoding/json"
	"fmt"

	policyAuditor "AWS-audit/internal/iam/policy"
	utils "AWS-audit/internal/utils"
	"AWS-audit/internal/vuln"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	//"github.com/aws/aws-sdk-go/service/s3control"
)

func Audit() {

	s3ToAudit := utils.GetServicesToAudit()

	if s3ToAudit.S3 == nil {
		utils.PrintInfo("No S3 configuration found")
		return
	}

	// Create a new session in the us-west-2 region
	sess := session.Must(session.NewSession(
		&aws.Config{
			Region: aws.String("us-east-2")}),
	)

	// if wildcard is preset all buckets in the account are audited
	if utils.CheckWildCardInStringArray(s3ToAudit.S3) {
		buckets := listBuckets(sess)
		if len(buckets) == 0 {
			utils.PrintInfo("No buckets found")
			return
		}
		s3ToAudit.S3 = buckets
	}

	utils.PrintInfo("Auditing S3")

	// get all bucket's regions
	var bucketRegion = make(map[string]string)
	for _, bucket := range s3ToAudit.S3 {
		region := getBucketRegion(sess, bucket)
		if region == "" {
			utils.PrintError("Unable to find bucket region")
		}
		if bucketRegion[bucket] == "" {
			bucketRegion[bucket] = region
		}
	}

	for _, bucket := range s3ToAudit.S3 {

		// audit each bucket policy in s3ToAudit
		utils.PrintInfo("Auditing bucket policy for " + bucket)
		runS3PolicyAudit(sess, bucket, bucketRegion[bucket])

		// audit each access point policy for each bucket in s3ToAudit
		utils.PrintInfo("Auditing access points for " + bucket)
		runS3AccessPointPolicyAudit(sess, bucket, bucketRegion[bucket], s3ToAudit.AccountId)

		// audit each bucket acl in s3ToAudit
		utils.PrintInfo("Auditing bucket ACL for " + bucket)
		runS3AclAudit(sess, bucket, bucketRegion[bucket], s3ToAudit.AccountId)

		// audit each bucket puclic access in s3ToAudit
		utils.PrintInfo("Auditing bucket PublicAccessBlock for " + bucket)
		runS3PublicAccessBlockAudit(sess, bucket, bucketRegion[bucket], s3ToAudit.AccountId)

		// audit each bucket encryption in s3ToAudit
		utils.PrintInfo("Auditing bucket encryption for " + bucket)
		runS3EncryptionConfigurationAudit(sess, bucket, bucketRegion[bucket])

		// audit each bucket lifecycle in s3ToAudit
		utils.PrintInfo("Auditing bucket lifecycle and MFA for " + bucket)
		runS3VersioningAudit(sess, bucket, bucketRegion[bucket])

		// audit each bucket logging in s3ToAudit
		utils.PrintInfo("Auditing bucket logging for " + bucket)
		runS3LoggingAudit(sess, bucket, bucketRegion[bucket])

		// audit each bucket website in s3ToAudit
		utils.PrintInfo("Auditing bucket website enabled for " + bucket)
		runS3WebSiteAudit(sess, bucket, bucketRegion[bucket])
	}

	utils.PrintInfo("Auditing S3 complete")
}

// start audit bucket policy
func runS3PolicyAudit(sess *session.Session, bucket string, region string) {

	svc := s3.New(sess, aws.NewConfig().WithRegion(region))

	// get bucket policy
	result, err := svc.GetBucketPolicy(&s3.GetBucketPolicyInput{
		Bucket: aws.String(bucket),
	})

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchBucket:
				utils.PrintError(fmt.Sprintf("Bucket %q does not exist.", bucket))
			case "NoSuchBucketPolicy":
				utils.PrintError(fmt.Sprintf("Bucket %q does not have a policy.", bucket))
			}
		}
		utils.PrintError(fmt.Sprintf("Unable to get bucket %q policy, %v.", bucket, err))
		return
	}

	// unmarshal policy
	var myPolicy utils.PolicyDocument
	err1 := json.Unmarshal([]byte(aws.StringValue(result.Policy)), &myPolicy)
	if err1 != nil {
		utils.PrintError(fmt.Sprintf("Unable to parse policy, %v.", err1))
		return
	}

	// audit bucket policy
	policyAuditor.RunPolicyAudit("Bucket", bucket, myPolicy)
}

// start audit access point policy of a bucket
func runS3AccessPointPolicyAudit(sess *session.Session, bucket string, region string, accountId string) {

	accessPointsName := listBucketAccessPoints(sess, bucket, region, accountId)

	if len(accessPointsName) == 0 {
		return
	}

	for _, accessPointName := range accessPointsName {
		policy := getAccessPointPolicy(sess, accountId, region, accessPointName)

		if policy == "" {
			continue
		}

		// unmarshal policyDocument
		var myPolicy utils.PolicyDocument
		err1 := json.Unmarshal([]byte(policy), &myPolicy)
		if err1 != nil {
			utils.PrintError(fmt.Sprintf("Unable to parse policy, %v.", err1))
			continue
		}

		// audit access point policy
		policyAuditor.RunPolicyAudit("Access Point", accessPointName, myPolicy)

	}
}

// start audit ACL of a bucket
func runS3AclAudit(sess *session.Session, bucket string, region string, accountId string) {

	svc := s3.New(sess, aws.NewConfig().WithRegion(region))

	// get bucket acl
	result, err := svc.GetBucketAcl(&s3.GetBucketAclInput{
		Bucket: aws.String(bucket),
	})

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchBucket:
				utils.PrintError(fmt.Sprintf("Bucket %q does not exist.", bucket))
			}
		}
		utils.PrintError(fmt.Sprintf("Unable to get bucket %q ACL, %v.", bucket, err))
		return
	}

	checkAcl("BucketAcl", bucket, result)
}

func checkAcl(serviceName string, service string, acl *s3.GetBucketAclOutput) {

	owner := aws.StringValue(acl.Owner.DisplayName)

	for _, grant := range acl.Grants {

		if grant.Grantee.URI != nil {
			// check public access
			if aws.StringValue(grant.Grantee.URI) == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" || aws.StringValue(grant.Grantee.URI) == "http://acs.amazonaws.com/groups/global/AllUsers" {
				result := fmt.Sprintf(serviceName+" has a grant with URI %s, permission %s", aws.StringValue(grant.Grantee.URI), aws.StringValue(grant.Permission))
				vuln.NewVulnerability(vuln.S3ACLPublic, result, vuln.AmazonS3, service, vuln.SeverityHigh)
				utils.PrintOutputCritical(result)
			}
			// check logdelivery permissions
			if aws.StringValue(grant.Grantee.URI) == "http://acs.amazonaws.com/groups/s3/LogDelivery" {
				result := fmt.Sprintf(serviceName+" has a grant with URI %s, permission %s", aws.StringValue(grant.Grantee.URI), aws.StringValue(grant.Permission))
				vuln.NewVulnerability(vuln.S3ACLPublic, result, vuln.AmazonS3, service, vuln.SeverityMedium)
				utils.PrintOutputMedium(result)
			}

		}

		// check if there are some grants with display name different than owner
		if grant.Grantee.DisplayName != nil {
			if aws.StringValue(grant.Grantee.DisplayName) != owner {
				result := fmt.Sprintf(serviceName+" has a grant with display name %s, permission %s", aws.StringValue(grant.Grantee.DisplayName), aws.StringValue(grant.Permission))
				vuln.NewVulnerability(vuln.S3ACLPublic, result, vuln.AmazonS3, service, vuln.SeverityHigh)
				utils.PrintOutputCritical(result)
			}
		}

	}
}

// start audit Public Access of a bucket
func runS3PublicAccessBlockAudit(sess *session.Session, bucket string, region string, accountId string) {

	svc := s3.New(sess, aws.NewConfig().WithRegion(region))

	// get public access block
	result, err := svc.GetPublicAccessBlock(&s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucket),
	})

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchBucket:
				utils.PrintError(fmt.Sprintf("Bucket %q does not exist.", bucket))
			}
		}
		utils.PrintError(fmt.Sprintf("Unable to get bucket %q public access block, %v.", bucket, err))
		return
	}

	checkPublicAccessBlock("PublicAccessBlock", bucket, result)
}

func checkPublicAccessBlock(serviceName string, bucket string, publicAccessBlock *s3.GetPublicAccessBlockOutput) {

	if !aws.BoolValue(publicAccessBlock.PublicAccessBlockConfiguration.BlockPublicAcls) {
		result := fmt.Sprintf(serviceName+" has a blockPublicAcls set to false for bucket %s", bucket)
		vuln.NewVulnerability(vuln.S3BlockPublicAccess, result, vuln.AmazonS3, bucket, vuln.SeverityHigh)
		utils.PrintOutputCritical(result)
	}
	if !aws.BoolValue(publicAccessBlock.PublicAccessBlockConfiguration.BlockPublicPolicy) {
		result := fmt.Sprintf(serviceName+" has a blockPublicPolicy set to false for bucket %s", bucket)
		vuln.NewVulnerability(vuln.S3BlockPublicAccess, result, vuln.AmazonS3, bucket, vuln.SeverityHigh)
		utils.PrintOutputCritical(result)
	}
	if !aws.BoolValue(publicAccessBlock.PublicAccessBlockConfiguration.IgnorePublicAcls) {
		result := fmt.Sprintf(serviceName+" has a ignorePublicAcls set to false for bucket %s", bucket)
		vuln.NewVulnerability(vuln.S3BlockPublicAccess, result, vuln.AmazonS3, bucket, vuln.SeverityHigh)
		utils.PrintOutputCritical(result)
	}
	if !aws.BoolValue(publicAccessBlock.PublicAccessBlockConfiguration.RestrictPublicBuckets) {
		result := fmt.Sprintf(serviceName+" has a restrictPublicBuckets set to false for bucket %s", bucket)
		vuln.NewVulnerability(vuln.S3BlockPublicAccess, result, vuln.AmazonS3, bucket, vuln.SeverityHigh)
		utils.PrintOutputCritical(result)
	}
}

// start audit Encryption of a bucket
func runS3EncryptionConfigurationAudit(sess *session.Session, bucket string, region string) {

	svc := s3.New(sess, aws.NewConfig().WithRegion(region))

	result, err := svc.GetBucketEncryption(&s3.GetBucketEncryptionInput{
		Bucket: aws.String(bucket),
	})

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchBucket:
				utils.PrintError(fmt.Sprintf("Bucket %q does not exist.", bucket))
			}
		}
		// Return not required, meaning that the bucket does not have encryption
		//utils.PrintError(fmt.Sprintf("Unable to get bucket %q encryption configuration, %v.", bucket, err))
		//return
	}

	if result.ServerSideEncryptionConfiguration == nil {
		result1 := fmt.Sprintf("Bucket encryption is not present for bucket %s", bucket)
		vuln.NewVulnerability(vuln.S3Encryption, result1, vuln.AmazonS3, bucket, vuln.SeverityHigh)
		utils.PrintOutputCritical(result1)
	}
}

// start audit Versioning of a bucket
func runS3VersioningAudit(sess *session.Session, bucket string, region string) {

	svc := s3.New(sess, aws.NewConfig().WithRegion(region))

	result, err := svc.GetBucketVersioning(&s3.GetBucketVersioningInput{
		Bucket: aws.String(bucket),
	})

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchBucket:
				utils.PrintError(fmt.Sprintf("Bucket %q does not exist.", bucket))
			}
		}
		// Return not required, meaning that the bucket does not have versioning
		//utils.PrintError(fmt.Sprintf("Unable to get bucket %q versioning configuration, %v.", bucket, err))
		//return
	}

	if result.Status == nil {
		result1 := fmt.Sprintf("Bucket versioning is not present for bucket %s", bucket)
		utils.PrintOutputMedium(result1)
		vuln.NewVulnerability(vuln.S3Versioning, result1, vuln.AmazonS3, bucket, vuln.SeverityMedium)
	} else {
		if aws.StringValue(result.Status) == "Suspended" {
			result1 := fmt.Sprintf("Bucket versioning is not present for bucket %s", bucket)
			vuln.NewVulnerability(vuln.S3Versioning, result1, vuln.AmazonS3, bucket, vuln.SeverityMedium)
			utils.PrintOutputMedium(result1)
		}
	}

	if result.MFADelete == nil {
		result1 := fmt.Sprintf("Bucket MFA Delete is not present for bucket %s", bucket)
		vuln.NewVulnerability(vuln.S3DeleteMFA, result1, vuln.AmazonS3, bucket, vuln.SeverityMedium)
		utils.PrintOutputMedium(result1)
	} else {
		if aws.StringValue(result.MFADelete) == "Disabled" {
			result1 := fmt.Sprintf("Bucket MFA Delete is not present for bucket %s", bucket)
			vuln.NewVulnerability(vuln.S3DeleteMFA, result1, vuln.AmazonS3, bucket, vuln.SeverityMedium)
			utils.PrintOutputMedium(result1)
		}
	}
}

// start audit Logging of a bucket
func runS3LoggingAudit(sess *session.Session, bucket string, region string) {

	svc := s3.New(sess, aws.NewConfig().WithRegion(region))

	result, err := svc.GetBucketLogging(&s3.GetBucketLoggingInput{
		Bucket: aws.String(bucket),
	})

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchBucket:
				utils.PrintError(fmt.Sprintf("Bucket %q does not exist.", bucket))
			}
		}
		// Return not required, meaning that the bucket does not have logging
		//utils.PrintError(fmt.Sprintf("Unable to get bucket %q logging configuration, %v.", bucket, err))
		//return
	}

	if result.LoggingEnabled == nil {
		result1 := fmt.Sprintf("Bucket logging is not present for bucket %s", bucket)
		utils.PrintOutputCritical(result1)
		vuln.NewVulnerability(vuln.S3Logging, result1, vuln.AmazonS3, bucket, vuln.SeverityHigh)
	}
}

func runS3WebSiteAudit(sess *session.Session, bucket string, region string) {

	svc := s3.New(sess, aws.NewConfig().WithRegion(region))

	result, err := svc.GetBucketWebsite(&s3.GetBucketWebsiteInput{
		Bucket: aws.String(bucket),
	})

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchBucket:
				utils.PrintError(fmt.Sprintf("Bucket %q does not exist.", bucket))
			}
		}
		// Return not required, meaning that the bucket does not have website
		//utils.PrintError(fmt.Sprintf("Unable to get bucket %q website configuration, %v.", bucket, err))
		//return
	}

	if result.IndexDocument != nil {
		result1 := fmt.Sprintf("Bucket website is enabled for bucket %s", bucket)
		utils.PrintOutputMedium(result1)
		vuln.NewVulnerability(vuln.S3Website, result1, vuln.AmazonS3, bucket, vuln.SeverityHigh)
	}
}
