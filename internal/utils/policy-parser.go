package utils

import (
	"encoding/json"
	"fmt"
)

//https://github.com/aws/aws-sdk-go-v2/issues/225

type PolicyDocument struct {
	// 2012-10-17 or 2008-10-17 old policies, do NOT use this for new policies
	Version    string      `json:"Version"`
	Id         string      `json:"Id,omitempty"`
	Statements []Statement `json:"Statement"`
}

type Statement struct {
	Sid          string         `json:"Sid,omitempty"`          // statement ID, service specific
	Effect       string         `json:"Effect"`                 // Allow or Deny
	Principal    PrincipalValue `json:"Principal,omitempty"`    // principal that is allowed or denied
	NotPrincipal PrincipalValue `json:"NotPrincipal,omitempty"` // exception to a list of principals
	Action       Value          `json:"Action"`                 // allowed or denied action
	NotAction    Value          `json:"NotAction,omitempty"`    // matches everything except
	Resource     Value          `json:"Resource,omitempty"`     // object or objects that the statement covers
	NotResource  Value          `json:"NotResource,omitempty"`  // matches everything except
	Condition    ConditionValue `json:"Condition,omitempty"`    // conditions for when a policy is in effect
}

// AWS allows string or []string as value, we convert everything to []string to avoid casting
type Value []string

// AWS allows string es. "*", we convert everything to map[string]Value es {"AWS": {"*"}}
type PrincipalValue map[string]Value

type ConditionValue map[string]map[string]Value

func (condition *ConditionValue) UnmarshalJSON(b []byte) error {

	result := make(map[string]map[string]Value)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	for k, v := range raw {
		var value map[string]Value
		if err := json.Unmarshal(v, &value); err != nil {
			return err
		}
		result[k] = value
	}

	*condition = result

	return nil
}

// unmarshalljson to unmarshall Principal
func (principal *PrincipalValue) UnmarshalJSON(b []byte) error {
	//map[AWS:[arn:aws:iam::1111111111111111:user/testS3 arn:aws:iam::1111111111111111:user/LorenzoGrazian]]

	var a string
	json.Unmarshal(b, &a)

	if string(a) == "*" {
		*principal = map[string]Value{"AWS": {"*"}}
		return nil
	}
	// unmarshall inside Principal
	var raw interface{}
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	var p map[string]Value
	switch v := raw.(type) {
	case map[string]interface{}:
		p = make(map[string]Value)
		for k, v := range v {
			switch v := v.(type) {
			case string:
				p[k] = Value{v}
			case []interface{}:
				p[k] = Value{}
				for _, v := range v {
					switch v := v.(type) {
					case string:
						p[k] = append(p[k], v)
					}
				}
			}
		}
	}

	*principal = p

	return nil
}

func (value *Value) UnmarshalJSON(b []byte) error {

	var raw interface{}
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	var p []string
	//  value can be string or []string, convert everything to []string
	switch v := raw.(type) {
	case string:
		p = []string{v}
	case []interface{}:
		var items []string
		for _, item := range v {
			items = append(items, fmt.Sprintf("%v", item))
		}
		p = items
	default:
		return fmt.Errorf("invalid %s value element: allowed is only string or []string", value)
	}

	*value = p
	return nil
}

func UnmarshalPolicyDocument(decodePolicy string) (*PolicyDocument, error) {
	var policyDocument *PolicyDocument
	err2 := json.Unmarshal([]byte(decodePolicy), &policyDocument)

	if err2 != nil {
		return nil, err2
	}
	return policyDocument, nil
}
