package S3

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

// get bucket region
func GetBucketRegion(bucket string, sess *session.Session) string {

	region, err := s3manager.GetBucketRegion(context.Background(), sess, "bucketaudit", "us-west-2")
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == "NotFound" {
			fmt.Println("unable to find bucket region not found")
		}
		return ""
	}

	fmt.Printf("Bucket is in %s region\n", region)

	return region
}
