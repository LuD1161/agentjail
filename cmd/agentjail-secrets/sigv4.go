package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// sigV4Sign signs an HTTP request with AWS Signature Version 4.
//
// This is a minimal implementation that handles POST requests to STS.
// It avoids the need for the heavy AWS SDK dependency (per ADR 0023).
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
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	// Set required headers.
	req.Header.Set("X-Amz-Date", amzDate)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}
	req.Header.Set("Host", req.URL.Host)

	// Payload hash.
	payloadHash := sha256Hex(bodyBytes)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	// Build canonical headers (sorted by header name, lowercased, trimmed).
	headers := make(map[string]string)
	for k, v := range req.Header {
		headers[strings.ToLower(k)] = strings.Join(v, ",")
	}
	headerNames := make([]string, 0, len(headers))
	for k := range headers {
		headerNames = append(headerNames, k)
	}
	sort.Strings(headerNames)

	var canonicalHeaders strings.Builder
	var signedHeaders strings.Builder
	for i, k := range headerNames {
		canonicalHeaders.WriteString(k)
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(strings.TrimSpace(headers[k]))
		canonicalHeaders.WriteString("\n")
		signedHeaders.WriteString(k)
		if i < len(headerNames)-1 {
			signedHeaders.WriteString(";")
		}
	}

	// Canonical query string (empty for POST).
	canonicalQueryString := ""

	// Canonical request.
	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		canonicalQueryString,
		canonicalHeaders.String(),
		signedHeaders.String(),
		payloadHash,
	}, "\n")

	// Credential scope.
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)

	// String to sign.
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	// Signing key.
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))

	// Signature.
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	// Authorization header.
	auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders.String(), signature)
	req.Header.Set("Authorization", auth)
}

// sha256Hex returns the hex-encoded SHA-256 hash of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// hmacSHA256 returns the HMAC-SHA256 of data using key.
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
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
