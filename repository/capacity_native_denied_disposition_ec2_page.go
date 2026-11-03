package repository

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"io"
	"strings"
)

// This separate decision-reader accepts an empty page with an opaque token;
// only its caller can declare completeness after the final closed empty page.
// The accepted-create exact-ID empty helper remains byte-for-byte unchanged.
func nativeDeniedEmptyInstancesPage(read model.CapacityOriginalCreateDispositionNativeRead) (string, bool) {
	next := ""
	valid := func() bool {
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
				} else if name == "nextToken" {
					if len(text) > 4096 || text != strings.TrimSpace(text) {
						return false
					}
					for _, c := range text {
						if c < '!' || c > '~' {
							return false
						}
					}
					next = text
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
	}()
	return next, valid
}
