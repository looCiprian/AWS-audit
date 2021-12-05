package utils

import (
	"fmt"
	"testing"
)

func TestUnmarshalPolicyDocument(t *testing.T) {

	inputPolicy := "{\"Id\":\"ExamplePolicy\",\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AllowSSLRequestsOnly\",\"Action\":\"s3:*\",\"Effect\":\"Deny\",\"Resource\":[\"arn:aws:s3:::DOC-EXAMPLE-BUCKET\",\"arn:aws:s3:::DOC-EXAMPLE-BUCKET/*\"],\"Condition\":{\"Bool\":{\"aws:SecureTransport1\":\"false\"}},\"Principal\":[\"*\"]}]}"

	policy, err := UnmarshalPolicyDocument(inputPolicy)

	if err != nil {
		t.Errorf("Error unmarshalling policy document: %s", err)
	}

	for _, statement := range policy.Statements {
		if statement.Condition == nil {
			t.Errorf("Condition is nil")
		}

		v, ok := statement.Condition["Bool"]["aws:SecureTransport1"]
		if !ok {
			t.Errorf("Condition is not set")
		}

		fmt.Println(v)

	}
}
