package S3

import (
	utils "AWS-audit/internal/utils"
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/s3control"
)

// get bucket region
func getBucketRegion(sess *session.Session, bucket string) string {

	region, err := s3manager.GetBucketRegion(context.Background(), sess, "bucketaudit", "us-west-2")
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == "NotFound" {
			utils.PrintError("unable to find bucket region not found")
		}
		return ""
	}

	//utils.PrintInfo(("Bucket is in %s region\n", region)

	return region
}

// list buckets in account
func listBuckets(sess *session.Session) []string {

	var buckets []string

	svc := s3.New(sess)

	result, err := svc.ListBuckets(nil)
	if err != nil {
		utils.PrintError(fmt.Sprintf("Unable to list buckets, %v.", err))
	}

	for _, b := range result.Buckets {
		buckets = append(buckets, aws.StringValue(b.Name))
	}

	return buckets
}

// list bucket access points
func listBucketAccessPoints(sess *session.Session, bucket string, region string, accountId string) []string {

	var accesspoints []string

	svc := s3control.New(sess, &aws.Config{Region: aws.String(region)})

	result, err := svc.ListAccessPoints(&s3control.ListAccessPointsInput{
		Bucket:    aws.String(bucket),
		AccountId: aws.String(accountId),
	})

	if err != nil {
		utils.PrintError(fmt.Sprintf("Unable to list bucket access points, %v.", err))
		return accesspoints
	}

	for _, b := range result.AccessPointList {
		accesspoints = append(accesspoints, aws.StringValue(b.Name))
	}

	return accesspoints
}

// get access point policy
func getAccessPointPolicy(sess *session.Session, accountId string, region string, accesspoint string) string {

	svc := s3control.New(sess, &aws.Config{Region: aws.String(region)})

	result, err := svc.GetAccessPointPolicy(&s3control.GetAccessPointPolicyInput{
		Name:      aws.String(accesspoint),
		AccountId: aws.String(accountId),
	})

	if err != nil {
		utils.PrintError(fmt.Sprintf("Unable to get access point policy, %v.", err))
		return ""
	}

	return aws.StringValue(result.Policy)
}
