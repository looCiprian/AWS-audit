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
)

// get bucket region
func getBucketRegion(bucket string, sess *session.Session) string {

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
