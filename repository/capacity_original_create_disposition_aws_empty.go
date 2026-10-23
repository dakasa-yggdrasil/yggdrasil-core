package repository

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"io"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const originalDispositionEC2Namespace = "http://ec2.amazonaws.com/doc/2016-11-15/"

// A successful exact-ID DescribeInstances call can return an explicitly empty
// reservationSet after the terminated instance is no longer returned. Preserve
// that original HTTP 200; only the complete retained EC2 XML can establish this
// absence branch. The independently pinned observer still owns the exact-ID
// request and the remaining five authenticated inventory reads.
func originalDispositionAWSExplicitEmptyInstances(read model.CapacityOriginalCreateDispositionNativeRead) bool {
	if read.Operation != "DescribeInstances" || read.ResourceKind != "aws_ec2_instance" || read.Status != 200 || read.ResponseRepresentation != "raw_http_body_v1" || read.ResponseBytes < 1 || read.ResponseBytes > 64<<10 || len(read.ResponseBodyBase64) > base64.StdEncoding.EncodedLen(64<<10) {
		return false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(read.ResponseBodyBase64)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != read.ResponseBodyBase64 || int64(len(raw)) != read.ResponseBytes || originalDispositionDigest(raw) != read.ResponseSHA256 {
		return false
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	root := xml.Name{Space: originalDispositionEC2Namespace, Local: "DescribeInstancesResponse"}
	started, finished, declaration := false, false, false
	seen := map[string]bool{}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return finished && seen["requestId"] && seen["reservationSet"]
		}
		if err != nil {
			return false
		}
		switch value := token.(type) {
		case xml.StartElement:
			if !started {
				if finished || value.Name != root || len(value.Attr) != 1 || value.Attr[0].Name != (xml.Name{Local: "xmlns"}) || value.Attr[0].Value != originalDispositionEC2Namespace {
					return false
				}
				started = true
				continue
			}
			name := value.Name.Local
			if finished || value.Name.Space != originalDispositionEC2Namespace || len(value.Attr) != 0 || seen[name] || name != "requestId" && name != "reservationSet" && name != "nextToken" {
				return false
			}
			text, ok := originalDispositionXMLScalar(decoder, value.Name)
			if !ok {
				return false
			}
			seen[name] = true
			if name == "requestId" {
				id := strings.Trim(text, " \t\r\n")
				if len(id) == 0 || len(id) > 128 {
					return false
				}
				for _, c := range id {
					if c < '!' || c > '~' {
						return false
					}
				}
			} else if !originalDispositionXMLWhitespace([]byte(text)) {
				return false
			}
		case xml.EndElement:
			if !started || finished || value.Name != root {
				return false
			}
			finished = true
		case xml.CharData:
			if !originalDispositionXMLWhitespace(value) {
				return false
			}
		case xml.ProcInst:
			if started || declaration || value.Target != "xml" {
				return false
			}
			declaration = true
		default:
			// Comments, DTDs, directives and unknown tokens cannot stand in for
			// an explicitly empty owning response.
			return false
		}
	}
}

func originalDispositionXMLScalar(decoder *xml.Decoder, name xml.Name) (string, bool) {
	var text strings.Builder
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", false
		}
		switch value := token.(type) {
		case xml.CharData:
			text.Write(value)
		case xml.EndElement:
			return text.String(), value.Name == name
		default:
			return "", false
		}
	}
}

func originalDispositionXMLWhitespace(raw []byte) bool {
	for _, c := range raw {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return false
		}
	}
	return true
}
