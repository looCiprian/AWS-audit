package S3

import (
	"encoding/json"
	"fmt"
	"strings"

	utils "AWS-audit/internal/utils"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
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

	// if wildcard is preset all buckets are audited
	if utils.CheckWildCard(s3ToAudit.S3) {
		s3ToAudit.S3 = listBuckets(sess)
	}

	utils.PrintInfo("Auditing S3")

	// for each bucket in s3ToAudit call run function
	for _, bucket := range s3ToAudit.S3 {
		utils.PrintInfo("Auditing " + bucket)
		run(sess, bucket)
	}

}

func run(sess *session.Session, bucket string) {

	// get bucket region
	region := getBucketRegion(bucket, sess)

	if region == "" {
		utils.PrintError("Unable to find bucket region")
	}

	svc := s3.New(sess, aws.NewConfig().WithRegion(region))

	// get bucket policy
	result, err := svc.GetBucketPolicy(&s3.GetBucketPolicyInput{
		Bucket: aws.String(bucket),
	})

	if err != nil {
		// Special error handling for the when the bucket doesn't
		// exists so we can give a more direct error message from the CLI.
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchBucket:
				utils.PrintError(fmt.Sprintf("Bucket %q does not exist.", bucket))
			case "NoSuchBucketPolicy":
				utils.PrintError(fmt.Sprintf("Bucket %q does not have a policy.", bucket))
			}
		}
		utils.PrintError(fmt.Sprintf("Unable to get bucket %q policy, %v.", bucket, err))
	}

	//utils.PrintInfo(aws.StringValue(result.Policy))

	var myPolicy utils.Policy
	err1 := json.Unmarshal([]byte(aws.StringValue(result.Policy)), &myPolicy)
	if err1 != nil {
		utils.PrintError(fmt.Sprintf("Unable to parse policy, %v.", err1))
	}

	//fmt.Println(aws.StringValue(result.Policy))
	//fmt.Println(myPolicy.Statements[0].Action[0])
	auditS3Policy(bucket, myPolicy)

}

func auditS3Policy(bucket string, policy utils.Policy) {

	for i, statement := range policy.Statements {
		// for each Principal in statement check if it contains *
		utils.PrintInfo("Checking principals for " + bucket)
		for _, principals := range statement.Principal {
			for _, principal := range principals {
				result := fmt.Sprintf("Bucket %s has a principal %s, actions: %s, effects: %s, resources: %s, conditions: %s", bucket, principal, policy.Statements[i].Action, policy.Statements[i].Effect, policy.Statements[i].Resource, policy.Statements[i].Condition)
				if checkWildCard(principal) {
					utils.PrintOutputCritical(result)
				} else {
					utils.PrintOutputLow(result)
				}
			}
		}

		utils.PrintInfo("Checking actions for " + bucket)
		// for each Action in statement check if it contains *
		if statement.Action != nil {
			for _, action := range statement.Action {
				result := fmt.Sprintf("Bucket %s has an action %s, principal %s, effects: %s, resources %s, conditions: %s", bucket, action, policy.Statements[i].Principal, policy.Statements[i].Effect, policy.Statements[i].Resource, policy.Statements[i].Condition)
				if checkWildCard(action) {
					utils.PrintOutputCritical(result)
				} else {
					utils.PrintOutputLow(result)
				}
			}
		}

	}

}

func checkWildCard(statement string) bool {
	return strings.Contains(statement, "*")
}
