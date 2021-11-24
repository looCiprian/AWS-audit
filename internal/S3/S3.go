package S3

import (
	"encoding/json"
	"fmt"

	utils "AWS-audit/internal/utils"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	//"github.com/aws/aws-sdk-go/service/s3control"
)

func Audit(s3ToAudit *utils.Audit) {

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
		s3ToAudit.S3 = listBuckets(sess)
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

	// audit each bucket policy in s3ToAudit
	for _, bucket := range s3ToAudit.S3 {
		utils.PrintInfo("Auditing " + bucket)
		runS3PolicyAudit(sess, bucket, bucketRegion[bucket])
	}

	// audit each access point policy for each bucket in s3ToAudit
	for _, bucket := range s3ToAudit.S3 {
		utils.PrintInfo("Auditing access points for " + bucket)
		// get bucket region
		runS3AccessPointPolicyAudit(sess, bucket, bucketRegion[bucket], s3ToAudit.AccountId)
	}

	// audit each bucket acl in s3ToAudit
	for _, bucket := range s3ToAudit.S3 {
		utils.PrintInfo("Auditing bucket ACL for " + bucket)
		runS3AclAudit(sess, bucket, bucketRegion[bucket], s3ToAudit.AccountId)
	}

	// audit each bucket puclic access in s3ToAudit
	for _, bucket := range s3ToAudit.S3 {
		utils.PrintInfo("Auditing bucket PublicAccessBlock for " + bucket)
		runS3PublicAccessBlockAudit(sess, bucket, bucketRegion[bucket], s3ToAudit.AccountId)
	}

	// audit each bucket encryption in s3ToAudit
	for _, bucket := range s3ToAudit.S3 {
		utils.PrintInfo("Auditing bucket encryption for " + bucket)
		runS3EncryptionConfigurationAudit(sess, bucket, bucketRegion[bucket])
	}

	// audit each bucket lifecycle in s3ToAudit
	for _, bucket := range s3ToAudit.S3 {
		utils.PrintInfo("Auditing bucket lifecycle and MFA for " + bucket)
		runS3VersioningAudit(sess, bucket, bucketRegion[bucket])
	}

	for _, bucket := range s3ToAudit.S3 {
		utils.PrintInfo("Auditing bucket logging for " + bucket)
		runS3LoggingAudit(sess, bucket, bucketRegion[bucket])
	}

	for _, bucket := range s3ToAudit.S3 {
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
	var myPolicy utils.Policy
	err1 := json.Unmarshal([]byte(aws.StringValue(result.Policy)), &myPolicy)
	if err1 != nil {
		utils.PrintError(fmt.Sprintf("Unable to parse policy, %v.", err1))
		return
	}

	// audit bucket policy
	auditS3Policy(bucket, myPolicy)

}

func auditS3Policy(bucket string, policy utils.Policy) {
	checkPolicyPrincipal("Bucket", bucket, policy)
	checkPolicyAction("Bucket", bucket, policy)
	checkPolicyResource("Bucket", bucket, policy)
}

// start audit access point of a bucket
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

		// unmarshal policy
		var myPolicy utils.Policy
		err1 := json.Unmarshal([]byte(policy), &myPolicy)
		if err1 != nil {
			utils.PrintError(fmt.Sprintf("Unable to parse policy, %v.", err1))
			continue
		}

		// audit access point policy
		auditS3AccessPointPolicy(accessPointName, myPolicy)

	}

}

func auditS3AccessPointPolicy(accessPointName string, policy utils.Policy) {
	checkPolicyPrincipal("Access Point", accessPointName, policy)
	checkPolicyAction("Access Point", accessPointName, policy)
	checkPolicyResource("Access Point", accessPointName, policy)
}

// audit principal of a policy
func checkPolicyPrincipal(serviceName string, service string, policy utils.Policy) {

	for i, statement := range policy.Statements {
		// for each Principal in statement check if it contains *
		utils.PrintInfo("Checking actions for " + serviceName + " " + service)
		for _, principals := range statement.Principal {
			for _, principal := range principals {
				result := fmt.Sprintf(serviceName+" %s has a principal %s, actions: %s, effects: %s, resources: %s, conditions: %s", service, principal, policy.Statements[i].Action, policy.Statements[i].Effect, policy.Statements[i].Resource, policy.Statements[i].Condition)
				if utils.CheckWildCardInString(principal) {
					utils.PrintOutputCritical(result)
				} else {
					utils.PrintOutputLow(result)
				}
			}
		}
	}
}

// audit action of a policy
func checkPolicyAction(serviceName string, service string, policy utils.Policy) {

	for i, statement := range policy.Statements {

		utils.PrintInfo("Checking actions for " + serviceName + " " + service)
		// for each Action in statement check if it contains *
		if statement.Action != nil {
			for _, action := range statement.Action {
				result := fmt.Sprintf(serviceName+" %s has an action %s, principal %s, effects: %s, resources %s, conditions: %s", service, action, policy.Statements[i].Principal, policy.Statements[i].Effect, policy.Statements[i].Resource, policy.Statements[i].Condition)
				if utils.CheckWildCardInString(action) {
					utils.PrintOutputCritical(result)
				} else {
					utils.PrintOutputLow(result)
				}
			}
		}

	}
}

// audit resource of a policy
func checkPolicyResource(serviceName string, service string, policy utils.Policy) {

	for i, statement := range policy.Statements {

		utils.PrintInfo("Checking resources for " + serviceName + " " + service)
		// for each Resource in statement check if it contains *
		if statement.Resource != nil {
			for _, resource := range statement.Resource {
				result := fmt.Sprintf(serviceName+" %s has a resource %s, actions: %s, principal %s, effects: %s, conditions: %s", service, resource, policy.Statements[i].Action, policy.Statements[i].Principal, policy.Statements[i].Effect, policy.Statements[i].Condition)
				if utils.CheckWildCardInString(resource) {
					utils.PrintOutputMedium(result)
				} else {
					utils.PrintOutputLow(result)
				}
			}
		}

	}
}

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
				utils.PrintOutputCritical(result)
			}
			// check logdelivery permissions
			if aws.StringValue(grant.Grantee.URI) == "http://acs.amazonaws.com/groups/s3/LogDelivery" {
				result := fmt.Sprintf(serviceName+" has a grant with URI %s, permission %s", aws.StringValue(grant.Grantee.URI), aws.StringValue(grant.Permission))
				utils.PrintOutputMedium(result)
			}

		}

		// check if there are some grants with display name different than owner
		if grant.Grantee.DisplayName != nil {
			if aws.StringValue(grant.Grantee.DisplayName) != owner {
				result := fmt.Sprintf(serviceName+" has a grant with display name %s, permission %s", aws.StringValue(grant.Grantee.DisplayName), aws.StringValue(grant.Permission))
				utils.PrintOutputCritical(result)
			}
		}

	}

}

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

	if aws.BoolValue(publicAccessBlock.PublicAccessBlockConfiguration.BlockPublicAcls) {
		result := fmt.Sprintf(serviceName+" has a blockPublicAcls set to true for bucket %s", bucket)
		utils.PrintOutputCritical(result)
	}
	if aws.BoolValue(publicAccessBlock.PublicAccessBlockConfiguration.BlockPublicPolicy) {
		result := fmt.Sprintf(serviceName+" has a blockPublicPolicy set to true for bucket %s", bucket)
		utils.PrintOutputCritical(result)
	}
	if aws.BoolValue(publicAccessBlock.PublicAccessBlockConfiguration.IgnorePublicAcls) {
		result := fmt.Sprintf(serviceName+" has a ignorePublicAcls set to true for bucket %s", bucket)
		utils.PrintOutputCritical(result)
	}
	if aws.BoolValue(publicAccessBlock.PublicAccessBlockConfiguration.RestrictPublicBuckets) {
		result := fmt.Sprintf(serviceName+" has a restrictPublicBuckets set to true for bucket %s", bucket)
		utils.PrintOutputCritical(result)
	}

}

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
	}

	if result.ServerSideEncryptionConfiguration == nil {
		result1 := fmt.Sprintf("Bucket encryption is not present for bucket %s", bucket)
		utils.PrintOutputCritical(result1)
	}

}

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
	}

	if result.Status == nil {
		result1 := fmt.Sprintf("Bucket versioning is not present for bucket %s", bucket)
		utils.PrintOutputCritical(result1)
	}

	if result.MFADelete == nil {
		result1 := fmt.Sprintf("Bucket MFA Delete is not present for bucket %s", bucket)
		utils.PrintOutputCritical(result1)
	}

}

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
	}

	if result.LoggingEnabled == nil {
		result1 := fmt.Sprintf("Bucket logging is not present for bucket %s", bucket)
		utils.PrintOutputCritical(result1)
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
	}

	if result.IndexDocument != nil {
		result1 := fmt.Sprintf("Bucket website is enabled for bucket %s", bucket)
		utils.PrintOutputMedium(result1)
	}

}
