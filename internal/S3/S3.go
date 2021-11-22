package S3

import (
	"encoding/json"
	"fmt"

	utils "AWS-audit/internal/utils"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

func S3() {


	// Create a new session in the us-west-2 region
	sess := session.Must(session.NewSession(
		&aws.Config{
			Region: aws.String("us-east-2")}),
	)

	Run(sess)

}

func Run(sess *session.Session){


	bucket := "bucketaudit"

	// get bucket region
	region := GetBucketRegion(bucket, sess)
	if region == "" {
		utils.PrintError("Unable to find bucket region")
	}

	// update session region
	sess.Config.Region = aws.String(region)

	svc := s3.New(sess)

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

	//mypolicy, err1 := policy.LoadPolicy([]byte(aws.StringValue(result.Policy)))

	var myPolicy utils.Policy
	err1 := json.Unmarshal([]byte(aws.StringValue(result.Policy)), &myPolicy)
	if err1 != nil {
		utils.PrintError(fmt.Sprintf("Unable to parse policy, %v.", err1))
	}

	fmt.Println(aws.StringValue(result.Policy))
	fmt.Println(myPolicy.Statements[0].Action[0])

}