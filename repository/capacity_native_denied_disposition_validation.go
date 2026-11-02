package repository

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// These are decision-evidence reads. No EBS/ENI empty-set assertion, native
// tuple, synthetic original HTTP403 or successful original return is accepted.
func validateNativeDeniedObservation(c model.CapacityNativeDeniedCandidate, o model.CapacityNativeDeniedObservation, began, now time.Time, maxAge time.Duration) error {
	r := c.Request
	if maxAge <= 0 {
		return ErrOriginalCreateDisposition
	}
	if maxAge > 30*time.Second {
		maxAge = 30 * time.Second
	}
	if o.Schema != model.NativeDeniedObservationSchema || !reflect.DeepEqual(o.Request, r) || r.Schema != model.NativeDeniedReadRequestSchema || r.OriginalAdapterSourceCommit != nativeDeniedOriginalAWSCreator || !originalDispositionHex(o.AdapterSourceCommit, 40) || o.Decision != "authorization_denied" || !o.HistoricalProfileRequestMatched || !o.SameTokenInstancesEmpty || o.OriginalHTTPResponseAvailable || o.NativeMutations != 0 || o.GuestAdmissionOrBusinessOrSavingsAuthority || !regexp.MustCompile(`^[0-9]{12}$`).MatchString(o.AccountID) || o.PrincipalARN != "arn:aws:iam::"+o.AccountID+":user/scopedcapacity-provider-aws-20261021" || !validCapacityExecutor(o.EventID) || !validCapacityExecutor(o.RequestID) || o.ClientToken != originalDispositionDigest([]byte(r.GrantID+":"+r.RequestSHA256)) || o.ObservationStartedAt.Before(began.Add(-5*time.Second)) || o.ObservationStartedAt.IsZero() || o.ObservedAt.Before(o.ObservationStartedAt) || o.ObservedAt.After(now.Add(5*time.Second)) || now.Sub(o.ObservedAt) > maxAge || o.ObservedAt.Sub(o.ObservationStartedAt) > 60*time.Second || len(o.NativeReads) < 3 || len(o.NativeReads) > 33 {
		return ErrOriginalCreateDisposition
	}
	var spec model.CapacityPolicySpec
	raw := c.Original.OriginalPolicy.Spec
	if json.Unmarshal(raw, &spec) != nil {
		return ErrOriginalCreateDisposition
	}
	regionMatched := false
	for _, p := range spec.Profiles {
		if p.Name == r.Profile && p.Provider == "aws" && p.Region == o.Region {
			regionMatched = true
		}
	}
	if !regionMatched {
		return ErrOriginalCreateDisposition
	}
	start := r.GrantCreatedAt.Truncate(time.Second)
	end := r.SettlementObservedAt.Truncate(time.Second).Add(time.Second)
	if r.GrantCreatedAt.IsZero() || r.SettlementObservedAt.Before(r.GrantCreatedAt) || !r.SettlementObservedAt.Before(r.OriginalDeadline) || o.DeniedAt.Before(start) || !o.DeniedAt.Before(end) {
		return ErrOriginalCreateDisposition
	}
	count := 0
	trailPages, instancePages := 0, 0
	instancePhase := false
	trailTokens, instanceTokens := map[string]bool{}, map[string]bool{}
	seenEventIDs := map[string]bool{}
	var previous time.Time
	total := int64(0)
	for i, read := range o.NativeReads {
		if read.Status != 200 || read.ResponseBytes < 2 || read.ResponseBytes > 64<<10 || read.CalledAt.Before(o.ObservationStartedAt) || read.ReturnedAt.Before(read.CalledAt) || read.ReturnedAt.After(o.ObservedAt) || !previous.IsZero() && read.CalledAt.Before(previous) {
			return ErrOriginalCreateDisposition
		}
		body, err := base64.StdEncoding.Strict().DecodeString(read.ResponseBodyBase64)
		if err != nil || base64.StdEncoding.EncodeToString(body) != read.ResponseBodyBase64 || int64(len(body)) != read.ResponseBytes || originalDispositionDigest(body) != read.ResponseSHA256 {
			return ErrOriginalCreateDisposition
		}
		previous = read.ReturnedAt
		total += read.ResponseBytes
		if total > 1<<20 {
			return ErrOriginalCreateDisposition
		}
		if i == 0 {
			if read.ResponseRepresentation != "raw_http_body_v1" || read.Operation != "GetCallerIdentity" || read.ResourceKind != "aws_account" || read.ResourceID != o.AccountID || !nativeDeniedSTSIdentity(body, o.AccountID, o.PrincipalARN) {
				return ErrOriginalCreateDisposition
			}
			continue
		}
		if read.Operation == "DescribeInstances" {
			instancePhase = true
			instancePages++
			if trailPages == 0 || instancePages > 16 || read.ResponseRepresentation != "raw_http_body_v1" || read.ResourceID != o.ClientToken {
				return ErrOriginalCreateDisposition
			}
			next, valid := nativeDeniedEmptyInstancesPage(read)
			if !valid || (next != "") != (i < len(o.NativeReads)-1) || next != "" && instanceTokens[next] {
				return ErrOriginalCreateDisposition
			}
			if next != "" {
				instanceTokens[next] = true
			}
			continue
		}
		trailPages++
		if instancePhase || trailPages > 16 {
			return ErrOriginalCreateDisposition
		}
		if read.ResponseRepresentation != "cloudtrail_lookup_events_userdata_omitted_projection_v1" || read.Operation != "LookupEvents" || read.ResourceKind != "aws_cloudtrail_event" || read.ResourceID != o.ClientToken || !nativeDeniedUniqueJSON(body) {
			return ErrOriginalCreateDisposition
		}
		var projected struct {
			Schema   string          `json:"schema"`
			Retained *bool           `json:"original_http_body_retained"`
			Hashed   *bool           `json:"original_http_body_hashed"`
			Closed   *bool           `json:"original_eof_and_close"`
			Removed  *int            `json:"user_data_fields_removed"`
			Response json.RawMessage `json:"response"`
		}
		if json.Unmarshal(body, &projected) != nil || projected.Schema != "cloudtrail_lookup_events_userdata_omitted_projection_v1" || projected.Retained == nil || *projected.Retained || projected.Hashed == nil || *projected.Hashed || projected.Closed == nil || !*projected.Closed || projected.Removed == nil || *projected.Removed < 0 || projected.Response == nil {
			return ErrOriginalCreateDisposition
		}
		body = projected.Response
		var page struct {
			Events []struct {
				EventID         string `json:"EventId"`
				CloudTrailEvent string `json:"CloudTrailEvent"`
			} `json:"Events"`
			NextToken string `json:"NextToken"`
		}
		var keys map[string]json.RawMessage
		if json.Unmarshal(body, &page) != nil || json.Unmarshal(body, &keys) != nil || keys["Events"] == nil || page.Events == nil || len(page.Events) > 50 || *projected.Removed > len(page.Events) || (page.NextToken != "") != (i+1 < len(o.NativeReads) && o.NativeReads[i+1].Operation == "LookupEvents") || page.NextToken != "" && trailTokens[page.NextToken] {
			return ErrOriginalCreateDisposition
		}
		if page.NextToken != "" {
			trailTokens[page.NextToken] = true
		}
		for _, event := range page.Events {
			if event.EventID == "" || seenEventIDs[event.EventID] || !nativeDeniedUniqueJSON([]byte(event.CloudTrailEvent)) {
				return ErrOriginalCreateDisposition
			}
			seenEventIDs[event.EventID] = true
			var e struct {
				EventID     string    `json:"eventID"`
				EventName   string    `json:"eventName"`
				EventSource string    `json:"eventSource"`
				EventTime   time.Time `json:"eventTime"`
				Region      string    `json:"awsRegion"`
				Recipient   string    `json:"recipientAccountId"`
				RequestID   string    `json:"requestID"`
				ErrorCode   string    `json:"errorCode"`
				User        struct {
					ARN     string `json:"arn"`
					Account string `json:"accountId"`
					Type    string `json:"type"`
				} `json:"userIdentity"`
				Request struct {
					Token    string          `json:"clientToken"`
					UserData json.RawMessage `json:"userData"`
				} `json:"requestParameters"`
				Response  json.RawMessage `json:"responseElements"`
				Resources json.RawMessage `json:"resources"`
			}
			if json.Unmarshal([]byte(event.CloudTrailEvent), &e) != nil {
				return ErrOriginalCreateDisposition
			}
			if len(e.Request.UserData) != 0 {
				return ErrOriginalCreateDisposition
			}
			if e.Request.Token != o.ClientToken {
				continue
			}
			count++
			if count != 1 || event.EventID != e.EventID || e.EventID != o.EventID || e.RequestID != o.RequestID || e.EventSource != "ec2.amazonaws.com" || e.EventName != "RunInstances" || e.ErrorCode != "Client.UnauthorizedOperation" || e.Region != o.Region || e.Recipient != o.AccountID || e.User.Account != o.AccountID || e.User.Type != "IAMUser" || e.User.ARN != o.PrincipalARN || !e.EventTime.Equal(o.DeniedAt) || string(bytes.TrimSpace(e.Response)) != "null" || len(e.Resources) != 0 && string(bytes.TrimSpace(e.Resources)) != "null" && string(bytes.TrimSpace(e.Resources)) != "[]" {
				return ErrOriginalCreateDisposition
			}
		}
	}
	if count != 1 || instancePages == 0 {
		return ErrOriginalCreateDisposition
	}
	return nil
}

// Reject duplicate keys at every depth before any SDK-shaped JSON projection.
func nativeDeniedUniqueJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var value func(int) bool
	value = func(depth int) bool {
		nodes++
		if depth > 32 || nodes > 50000 {
			return false
		}
		t, e := d.Token()
		if e != nil {
			return false
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok || seen[s] {
					return false
				}
				seen[s] = true
				if !value(depth + 1) {
					return false
				}
			}
			t, e = d.Token()
			return e == nil && t == json.Delim('}')
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			t, e = d.Token()
			return e == nil && t == json.Delim(']')
		}
		return false
	}
	if !value(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
func nativeDeniedSTSIdentity(raw []byte, account, arn string) bool {
	d := xml.NewDecoder(bytes.NewReader(raw))
	var path []string
	seen := map[string]bool{}
	root := false
	for {
		t, e := d.Token()
		if e == io.EOF {
			return root && len(path) == 0 && seen["Account"] && seen["Arn"]
		}
		if e != nil {
			return false
		}
		switch x := t.(type) {
		case xml.StartElement:
			if len(path) == 0 {
				if root || x.Name.Local != "GetCallerIdentityResponse" || x.Name.Space != "https://sts.amazonaws.com/doc/2011-06-15/" {
					return false
				}
				root = true
			}
			path = append(path, x.Name.Local)
			if strings.Join(path, "/") == "GetCallerIdentityResponse/GetCallerIdentityResult/Account" || strings.Join(path, "/") == "GetCallerIdentityResponse/GetCallerIdentityResult/Arn" {
				if seen[x.Name.Local] {
					return false
				}
				seen[x.Name.Local] = true
				var v string
				if d.DecodeElement(&v, &x) != nil {
					return false
				}
				if x.Name.Local == "Account" && v != account || x.Name.Local == "Arn" && v != arn {
					return false
				}
				path = path[:len(path)-1]
			}
		case xml.EndElement:
			if len(path) == 0 {
				return false
			}
			path = path[:len(path)-1]
		case xml.Directive, xml.Comment:
			return false
		case xml.CharData:
			if len(path) == 0 && len(bytes.TrimSpace(x)) != 0 {
				return false
			}
		case xml.ProcInst:
			if root || x.Target != "xml" {
				return false
			}
		}
	}
}
