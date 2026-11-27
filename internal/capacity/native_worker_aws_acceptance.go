package capacity

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Private transport custody, mirrored exactly from AWS57. Never return this
// envelope, raw XML, or its digest through a public workflow result.
type nativeAWSOriginal struct {
	Schema             string `json:"schema"`
	AttemptID          string `json:"attempt_id"`
	HTTPStatus         int    `json:"http_status"`
	RequestID          string `json:"request_id"`
	TransportCompleted bool   `json:"transport_completed"`
	Body               []byte `json:"body"`
}
type nativeAWSAcceptance struct {
	requestID, resourceID, accountID, imageID, instanceType, networkID, subnetID string
	zone, nativeIPv4, mac, clientToken, interfaceID, rootVolumeID, rootDevice    string
	createdAt                                                                    time.Time
	tags                                                                         model.CapacityNativeWorkerObservedTags
	rootVolumePresent, rootDevicePresent, interfaceIDPresent                     bool
}

type nativeAWSXML struct {
	name     string
	text     string
	children []*nativeAWSXML
}

func (n *nativeAWSXML) child(key string) *nativeAWSXML {
	for _, c := range n.children {
		if c.name == key {
			return c
		}
	}
	return nil
}
func (n *nativeAWSXML) value(path ...string) string {
	for _, key := range path {
		if n == nil {
			return ""
		}
		n = n.child(key)
	}
	if n == nil || len(n.children) != 0 {
		return ""
	}
	return n.text
}
func (n *nativeAWSXML) one(key string) *nativeAWSXML {
	n = n.child(key)
	if n == nil || n.text != "" || len(n.children) != 1 || n.children[0].name != "item" {
		return nil
	}
	return n.children[0]
}

// AWS Query XML is not JSON: a whole-token walk rejects repeated semantic
// members, alternative namespaces, directives/DTD, trailing roots and framing
// before any identity can be used as a read selector. Repeated item members
// are allowed only in actual AWS Set collections and are checked by their join.
func decodeNativeAWSXML(raw []byte) (*nativeAWSXML, error) {
	if len(raw) == 0 || len(raw) > 736<<10 {
		return nil, errNativePhysical
	}
	d := xml.NewDecoder(bytes.NewReader(raw))
	var stack []*nativeAWSXML
	var root *nativeAWSXML
	count := 0
	closed := false
	declaration := false
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errNativePhysical
		}
		switch v := t.(type) {
		case xml.ProcInst:
			if root != nil || declaration || v.Target != "xml" || (string(v.Inst) != `version="1.0" encoding="UTF-8"` && string(v.Inst) != `version="1.0"`) {
				return nil, errNativePhysical
			}
			declaration = true
		case xml.StartElement:
			count++
			if closed || count > 32768 || len(stack) >= 32 || v.Name.Space != "http://ec2.amazonaws.com/doc/2016-11-15/" {
				return nil, errNativePhysical
			}
			for _, a := range v.Attr {
				if len(stack) != 0 || a.Name.Space != "" || a.Name.Local != "xmlns" || a.Value != v.Name.Space {
					return nil, errNativePhysical
				}
			}
			n := &nativeAWSXML{name: v.Name.Local}
			if len(stack) == 0 {
				if root != nil || n.name != "RunInstancesResponse" || len(v.Attr) != 1 {
					return nil, errNativePhysical
				}
				root = n
			} else {
				p := stack[len(stack)-1]
				for _, prior := range p.children {
					if strings.EqualFold(prior.name, n.name) && !(prior.name == "item" && n.name == "item" && strings.HasSuffix(p.name, "Set")) {
						return nil, errNativePhysical
					}
				}
				p.children = append(p.children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errNativePhysical
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				closed = true
			}
		case xml.CharData:
			if len(stack) == 0 {
				if len(bytes.TrimSpace(v)) != 0 {
					return nil, errNativePhysical
				}
			} else {
				n := stack[len(stack)-1]
				n.text += string(v)
				if len(n.text) > 736<<10 {
					return nil, errNativePhysical
				}
			}
		default:
			return nil, errNativePhysical
		}
	}
	if root == nil || !closed || len(stack) != 0 {
		return nil, errNativePhysical
	}
	var validate func(*nativeAWSXML) bool
	validate = func(n *nativeAWSXML) bool {
		if len(n.children) != 0 {
			if strings.TrimSpace(n.text) != "" {
				return false
			}
			n.text = ""
		}
		for _, c := range n.children {
			if !validate(c) {
				return false
			}
		}
		return true
	}
	if !validate(root) {
		return nil, errNativePhysical
	}
	for _, n := range root.children {
		if n.name != "requestId" && n.name != "reservationId" && n.name != "ownerId" && n.name != "groupSet" && n.name != "instancesSet" {
			return nil, errNativePhysical
		}
	}
	return root, nil
}

func decodeNativeAWSAcceptance(a model.CapacityNativeWorkerAttempt, original model.CapacityNativeWorkerOriginalReturn) (nativeAWSAcceptance, error) {
	var out nativeAWSAcceptance
	var wire nativeAWSOriginal
	if !original.CaptureComplete || original.ErrorClass != "" || len(original.Wire) == 0 || len(original.Wire) > 1<<20 || DecodeNativeCapacity(json.RawMessage(original.Wire), &wire) != nil || wire.Schema != "aws_native_worker_original_return_v1" || wire.AttemptID != a.ID.String() || wire.HTTPStatus != 200 || !wire.TransportCompleted || (wire.RequestID != "" && !nativePhysicalRequestID(wire.RequestID)) {
		return out, errNativePhysical
	}
	root, err := decodeNativeAWSXML(wire.Body)
	if err != nil {
		return out, err
	}
	i := root.one("instancesSet")
	if i == nil {
		return out, errNativePhysical
	}
	// These are the official RunInstances instance members. Optional unrelated
	// members remain private and have no bearing on acceptance. Unknown future
	// top-level members fail closed rather than changing creation qualification.
	allowed := strings.Fields("amiLaunchIndex imageId instanceId instanceState privateDnsName dnsName reason keyName productCodes instanceType launchTime placement kernelId ramdiskId platform monitoring subnetId vpcId privateIpAddress ipAddress stateReason architecture rootDeviceType rootDeviceName blockDeviceMapping virtualizationType instanceLifecycle spotInstanceRequestId clientToken tagSet hypervisor networkInterfaceSet iamInstanceProfile ebsOptimized sriovNetSupport enaSupport sourceDestCheck cpuOptions capacityReservationId capacityReservationSpecification hibernationOptions licenses metadataOptions enclaveOptions bootMode platformDetails usageOperation usageOperationUpdateTime privateDnsNameOptions ipv6Address tpmSupport maintenanceOptions currentInstanceBootMode networkPerformanceOptions operator instanceMetadataTags")
	for _, n := range i.children {
		known := false
		for _, key := range allowed {
			if n.name == key {
				known = true
				break
			}
		}
		if !known {
			return out, errNativePhysical
		}
	}
	out.requestID = root.value("requestId")
	out.accountID = root.value("ownerId")
	out.resourceID = i.value("instanceId")
	out.imageID = i.value("imageId")
	out.instanceType = i.value("instanceType")
	out.networkID = i.value("vpcId")
	out.subnetID = i.value("subnetId")
	out.zone = i.value("placement", "availabilityZone")
	out.nativeIPv4 = i.value("privateIpAddress")
	out.clientToken = i.value("clientToken")
	out.rootDevice = i.value("rootDeviceName")
	out.createdAt, err = time.Parse(time.RFC3339Nano, i.value("launchTime"))
	if err != nil {
		return out, errNativePhysical
	}
	out.createdAt = out.createdAt.UTC()
	state := i.value("instanceState", "name")
	stateCode, codeErr := strconv.Atoi(i.value("instanceState", "code"))
	if !nativePhysicalRequestID(out.requestID) || wire.RequestID != "" && wire.RequestID != out.requestID || !regexp.MustCompile(`^i-[a-f0-9]{17}$`).MatchString(out.resourceID) || out.accountID != "153828470928" || !regexp.MustCompile(`^ami-[a-f0-9]{17}$`).MatchString(out.imageID) || out.instanceType == "" || out.networkID == "" || out.subnetID == "" || out.zone == "" || out.nativeIPv4 == "" || out.clientToken != a.ID.String() || codeErr != nil || !((state == "pending" && stateCode == 0) || (state == "running" && stateCode == 16)) || (i.child("rootDeviceType") != nil && i.value("rootDeviceType") != "ebs") || i.value("architecture") != "x86_64" {
		return out, errNativePhysical
	}
	nic := i.one("networkInterfaceSet")
	if nic == nil {
		return out, errNativePhysical
	}
	out.interfaceID = nic.value("networkInterfaceId")
	out.interfaceIDPresent = nic.child("networkInterfaceId") != nil
	out.mac = nic.value("macAddress")
	if out.interfaceIDPresent && !regexp.MustCompile(`^eni-[a-f0-9]{17}$`).MatchString(out.interfaceID) || out.mac == "" || nic.value("vpcId") != out.networkID || nic.value("subnetId") != out.subnetID || nic.value("privateIpAddress") != out.nativeIPv4 {
		return out, errNativePhysical
	}
	if attachment := nic.child("attachment"); attachment != nil {
		if attachment.child("deviceIndex") != nil && attachment.value("deviceIndex") != "0" || attachment.child("deleteOnTermination") != nil && attachment.value("deleteOnTermination") != "true" {
			return out, errNativePhysical
		}
	}
	out.rootDevicePresent = i.child("rootDeviceName") != nil
	if out.rootDevicePresent && out.rootDevice == "" {
		return out, errNativePhysical
	}
	// A pending RunInstances ACK may not yet contain ancillary resource IDs.
	// Absence is retained explicitly; a present but partial identity is refused.
	if collection := i.child("blockDeviceMapping"); collection != nil {
		if len(collection.children) != 0 {
			block := i.one("blockDeviceMapping")
			if block == nil || block.value("deviceName") == "" || (out.rootDevicePresent && block.value("deviceName") != out.rootDevice) || block.value("ebs", "deleteOnTermination") != "true" {
				return out, errNativePhysical
			}
			out.rootVolumeID = block.value("ebs", "volumeId")
			out.rootVolumePresent = true
			if !regexp.MustCompile(`^vol-[a-f0-9]{17}$`).MatchString(out.rootVolumeID) {
				return out, errNativePhysical
			}
		} else if collection.text != "" {
			return out, errNativePhysical
		}
	}
	tags := i.child("tagSet")
	if tags == nil {
		return out, errNativePhysical
	}
	seen := map[string]bool{}
	expected := map[string]string{"yggdrasil.io/native-worker-attempt": a.ID.String(), "dakasa.io/native-worker-pool": a.PoolUID, "yggdrasil.io/native-worker-launch-sha256": a.LaunchSHA256}
	for _, tag := range tags.children {
		if tag.name != "item" {
			return out, errNativePhysical
		}
		key := tag.value("key")
		if seen[key] {
			return out, errNativePhysical
		}
		seen[key] = true
		if value, known := expected[key]; known && tag.value("value") != value {
			return out, errNativePhysical
		}
	}
	for key := range expected {
		if !seen[key] {
			return out, errNativePhysical
		}
	}
	out.tags = model.CapacityNativeWorkerObservedTags{AttemptID: a.ID.String(), PoolUID: a.PoolUID, LaunchSHA256: a.LaunchSHA256}
	return out, nil
}
