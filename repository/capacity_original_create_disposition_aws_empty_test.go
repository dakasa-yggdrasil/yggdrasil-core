package repository

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Declared EC2 Query XML fixture, matching the publicly observed response shape;
// this fixture is not a provider observation or an original disposition proof.
const originalDispositionEmptyInstancesXML = `<?xml version="1.0" encoding="UTF-8"?>
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
 <requestId>7f07aca4-1901-4cd6-bb42-7cc8a251ab06</requestId>
 <reservationSet/>
</DescribeInstancesResponse>`

func originalDispositionEmptyRead(t *testing.T, xml string) model.CapacityOriginalCreateDispositionNativeRead {
	t.Helper()
	_, o, _ := originalDispositionAWSAdjunctFixture(t)
	r := o.NativeReads[1]
	raw := []byte(xml)
	r.ResponseBodyBase64 = base64.StdEncoding.EncodeToString(raw)
	r.ResponseBytes = int64(len(raw))
	r.ResponseSHA256 = originalDispositionDigest(raw)
	return r
}

func TestOriginalDispositionAWSExplicitEmptyXML(t *testing.T) {
	for name, value := range map[string]string{
		"explicit_empty":                  originalDispositionEmptyInstancesXML,
		"whitespace_and_empty_next_token": strings.Replace(originalDispositionEmptyInstancesXML, "<reservationSet/>", "<reservationSet> \n\t</reservationSet><nextToken> \r\n</nextToken>", 1),
		"without_declaration":             strings.Replace(originalDispositionEmptyInstancesXML, `<?xml version="1.0" encoding="UTF-8"?>`, "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if !originalDispositionAWSExplicitEmptyInstances(originalDispositionEmptyRead(t, value)) {
				t.Fatal("complete explicitly empty EC2 response refused")
			}
		})
	}
	for name, value := range map[string]string{
		"instance_present":       strings.Replace(originalDispositionEmptyInstancesXML, "<reservationSet/>", "<reservationSet><item><instancesSet/></item></reservationSet>", 1),
		"reservation_omitted":    strings.Replace(originalDispositionEmptyInstancesXML, "<reservationSet/>", "", 1),
		"request_omitted":        strings.Replace(originalDispositionEmptyInstancesXML, "<requestId>7f07aca4-1901-4cd6-bb42-7cc8a251ab06</requestId>", "", 1),
		"request_empty":          strings.Replace(originalDispositionEmptyInstancesXML, "7f07aca4-1901-4cd6-bb42-7cc8a251ab06", " \t", 1),
		"request_nonprintable":   strings.Replace(originalDispositionEmptyInstancesXML, "7f07aca4-1901-4cd6-bb42-7cc8a251ab06", "x&#10;y", 1),
		"request_too_long":       strings.Replace(originalDispositionEmptyInstancesXML, "7f07aca4-1901-4cd6-bb42-7cc8a251ab06", strings.Repeat("x", 129), 1),
		"next_page":              strings.Replace(originalDispositionEmptyInstancesXML, "<reservationSet/>", "<reservationSet/><nextToken>more</nextToken>", 1),
		"duplicate_reservation":  strings.Replace(originalDispositionEmptyInstancesXML, "<reservationSet/>", "<reservationSet/><reservationSet/>", 1),
		"duplicate_request":      strings.Replace(originalDispositionEmptyInstancesXML, "<reservationSet/>", "<reservationSet/><requestId>other</requestId>", 1),
		"duplicate_next_token":   strings.Replace(originalDispositionEmptyInstancesXML, "<reservationSet/>", "<reservationSet/><nextToken/><nextToken/>", 1),
		"unknown_element":        strings.Replace(originalDispositionEmptyInstancesXML, "<reservationSet/>", "<reservationSet/><unknown/>", 1),
		"root_attribute":         strings.Replace(originalDispositionEmptyInstancesXML, "<DescribeInstancesResponse ", `<DescribeInstancesResponse hidden="true" `, 1),
		"child_attribute":        strings.Replace(originalDispositionEmptyInstancesXML, "<reservationSet/>", `<reservationSet hidden="true"/>`, 1),
		"nil_reservation":        strings.Replace(originalDispositionEmptyInstancesXML, "<reservationSet/>", `<reservationSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"/>`, 1),
		"wrong_namespace":        strings.ReplaceAll(originalDispositionEmptyInstancesXML, originalDispositionEC2Namespace, "https://foreign.invalid/"),
		"missing_namespace":      strings.Replace(originalDispositionEmptyInstancesXML, ` xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"`, "", 1),
		"child_namespace":        strings.Replace(originalDispositionEmptyInstancesXML, "<reservationSet/>", `<reservationSet xmlns="https://foreign.invalid/"/>`, 1),
		"wrong_root":             strings.ReplaceAll(originalDispositionEmptyInstancesXML, "DescribeInstancesResponse", "DescribeImagesResponse"),
		"reservation_text":       strings.Replace(originalDispositionEmptyInstancesXML, "<reservationSet/>", "<reservationSet>unknown</reservationSet>", 1),
		"non_XML_whitespace":     strings.Replace(originalDispositionEmptyInstancesXML, "<reservationSet/>", "<reservationSet>&#160;</reservationSet>", 1),
		"nested_request":         strings.Replace(originalDispositionEmptyInstancesXML, "<requestId>", "<requestId><nested/>", 1),
		"trailing_root":          originalDispositionEmptyInstancesXML + "<DescribeInstancesResponse/>",
		"trailing_text":          originalDispositionEmptyInstancesXML + "unknown",
		"truncated":              strings.TrimSuffix(originalDispositionEmptyInstancesXML, "</DescribeInstancesResponse>"),
		"comment":                strings.Replace(originalDispositionEmptyInstancesXML, "<reservationSet/>", "<reservationSet/><!-- unknown -->", 1),
		"DTD":                    strings.Replace(originalDispositionEmptyInstancesXML, "<DescribeInstancesResponse ", "<!DOCTYPE DescribeInstancesResponse><DescribeInstancesResponse ", 1),
		"processing_instruction": originalDispositionEmptyInstancesXML + "<?unknown value?>",
		"error_XML":              "<Response><Errors><Error><Code>InvalidInstanceID.NotFound</Code></Error></Errors></Response>",
		"JSON_empty":             `{"Reservations":[]}`,
		"empty":                  "",
	} {
		t.Run(name, func(t *testing.T) {
			if originalDispositionAWSExplicitEmptyInstances(originalDispositionEmptyRead(t, value)) {
				t.Fatal("incomplete, nonempty or ambiguous response accepted as absence")
			}
		})
	}
}

func TestOriginalDispositionAWSExplicitEmptyRequiresOriginalRawExtent(t *testing.T) {
	r := originalDispositionEmptyRead(t, originalDispositionEmptyInstancesXML)
	for name, mutate := range map[string]func(*model.CapacityOriginalCreateDispositionNativeRead){
		"canonical_SDK_summary": func(r *model.CapacityOriginalCreateDispositionNativeRead) {
			r.ResponseRepresentation = "canonical_provider_SDK_result_v1"
		},
		"wrong_digest":      func(r *model.CapacityOriginalCreateDispositionNativeRead) { r.ResponseSHA256 = strings.Repeat("0", 64) },
		"wrong_extent":      func(r *model.CapacityOriginalCreateDispositionNativeRead) { r.ResponseBytes++ },
		"malformed_base64":  func(r *model.CapacityOriginalCreateDispositionNativeRead) { r.ResponseBodyBase64 += "!" },
		"unknown_operation": func(r *model.CapacityOriginalCreateDispositionNativeRead) { r.Operation = "DescribeImages" },
		"wrong_kind":        func(r *model.CapacityOriginalCreateDispositionNativeRead) { r.ResourceKind = "aws_account" },
		"status_400":        func(r *model.CapacityOriginalCreateDispositionNativeRead) { r.Status = 400 },
		"oversized":         func(r *model.CapacityOriginalCreateDispositionNativeRead) { r.ResponseBytes = (64 << 10) + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			mutate(&bad)
			if originalDispositionAWSExplicitEmptyInstances(bad) {
				t.Fatal("unjoined original raw response accepted")
			}
		})
	}
}

func TestOriginalDispositionAWS200EmptyAdjunctPreservesNativeStatusAndUnknownInventory(t *testing.T) {
	c, o, now := originalDispositionAWSAdjunctFixture(t)
	o.ResourceState = "absent"
	o.NativeReads[1] = originalDispositionEmptyRead(t, originalDispositionEmptyInstancesXML)
	if err := validateOriginalDispositionObservation(c, o, now.Add(-2*time.Second), now, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if o.NativeReads[1].Status != 200 || c.Request.OriginalAuxiliaryInventoryComplete || c.Request.OriginalCreateActionID == "" || len(o.NativeReads) != 6 {
		t.Fatal("native status, original unknown inventory or six-read evidence changed")
	}
	for name, mutate := range map[string]func(*model.CapacityOriginalCreateDispositionObservation){
		"response_not_explicit_empty": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.NativeReads[1] = originalDispositionEmptyRead(t, "<original-adjunct-read/>")
		},
		"missing_auxiliary_read": func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeReads = o.NativeReads[:5] },
		"wrong_instance":         func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeReads[1].ResourceID = "i-foreign" },
		"inventory_unknown":      func(o *model.CapacityOriginalCreateDispositionObservation) { o.AuxiliaryInventoryComplete = false },
		"not_absent":             func(o *model.CapacityOriginalCreateDispositionObservation) { o.ResourceState = "running" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := cloneDispositionObservation(o)
			mutate(&bad)
			if validateOriginalDispositionObservation(c, bad, now.Add(-2*time.Second), now, 30*time.Second) == nil {
				t.Fatal("empty response bypassed the original adjunct predicates")
			}
		})
	}
	// Both previously accepted branches retain their original meanings.
	originalCandidate, terminated, originalNow := originalDispositionAWSAdjunctFixture(t)
	if validateOriginalDispositionObservation(originalCandidate, terminated, originalNow.Add(-2*time.Second), originalNow, 30*time.Second) != nil {
		t.Fatal("original HTTP200 terminated branch changed")
	}
	notFound := cloneDispositionObservation(o)
	notFound.NativeReads[1].Status = 400
	if validateOriginalDispositionObservation(c, notFound, now.Add(-2*time.Second), now, 30*time.Second) != nil {
		t.Fatal("original HTTP400 absence branch changed")
	}
}
