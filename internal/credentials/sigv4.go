package credentials

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// sigV4Sign signs an HTTP request with AWS Signature Version 4
// using the official aws-sdk-go-v2 signer sub-package.
//
// Parameters:
//   - req: the HTTP request to sign (method, URL, headers, body must be set)
//   - bodyBytes: the raw request body bytes (used for the payload hash)
//   - accessKey: AWS access key ID
//   - secretKey: AWS secret access key
//   - sessionToken: AWS session token (optional, empty if not using temporary creds)
//   - region: AWS region (e.g. "us-east-1")
//   - service: AWS service name (e.g. "sts")
func sigV4Sign(req *http.Request, bodyBytes []byte, accessKey, secretKey, sessionToken, region, service string) {
	payloadHash := sha256Hex(bodyBytes)

	creds := aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		SessionToken:    sessionToken,
	}

	signer := v4.NewSigner()

	// SignHTTP mutates req by adding Authorization, X-Amz-Date, and
	// (if present) X-Amz-Security-Token headers.
	_ = signer.SignHTTP(context.Background(), creds, req, payloadHash, service, region, time.Now().UTC())
}

// sha256Hex returns the hex-encoded SHA-256 hash of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// buildAssumeRoleBody builds the URL-encoded form body for STS AssumeRole.
func buildAssumeRoleBody(roleARN, sessionName string, durationSeconds int, inlinePolicy string) (string, []byte) {
	form := url.Values{}
	form.Set("Action", "AssumeRole")
	form.Set("Version", "2011-06-15")
	form.Set("RoleArn", roleARN)
	form.Set("RoleSessionName", sessionName)
	form.Set("DurationSeconds", fmt.Sprintf("%d", durationSeconds))
	if inlinePolicy != "" {
		form.Set("Policy", inlinePolicy)
	}
	body := form.Encode()
	return body, []byte(body)
}

// scopePolicies maps scope names to inline session policies (JSON) that
// restrict what the STS session can do.  These are applied as inline session
// policies on the AssumeRole call, further restricting the role's permissions.
var scopePolicies = map[string]string{
	// read-only: deny all write/delete operations.
	"read-only": `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Deny",
				"Action": ["Delete*", "Terminate*", "Detach*", "Deregister*",
					"Remove*", "Disassociate*", "Cancel*", "Release*",
					"Stop*", "Suspend*", "Put*", "Create*", "Update*",
					"Set*", "Attach*", "Enable*", "Start*", "Publish*",
					"BatchWrite*", "S3:DeleteBucket", "S3:DeleteObject",
					"S3:PutObject", "IAM:Create*", "IAM:Delete*",
					"IAM:Update*", "IAM:Put*"],
				"Resource": "*"
			}
		]
	}`,
	// read-write: allow create/update but deny delete/terminate.
	"read-write": `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Deny",
				"Action": ["Delete*", "Terminate*", "Detach*", "Deregister*",
					"Remove*", "Disassociate*", "Cancel*"],
				"Resource": "*"
			}
		]
	}`,
}
