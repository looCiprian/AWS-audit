package utils

type Audit struct {
	S3     Buckets `yaml:"s3"`
	Lambda Lambdas `yaml:"lambda"`
}

type Buckets []string
type Lambdas []string