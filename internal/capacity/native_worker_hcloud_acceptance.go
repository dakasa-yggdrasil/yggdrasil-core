package capacity

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const nativeHCloudOriginalSchema = "hcloud_native_worker_original_return_v1"
const nativeHCloudWitnessSchema = "native_worker_hcloud_ack_witness_v1"

type nativeHCloudOriginal struct {
	Schema             string `json:"schema"`
	AttemptID          string `json:"attempt_id"`
	HTTPStatus         int    `json:"http_status"`
	RequestID          string `json:"request_id"`
	RequestIDObserved  bool   `json:"request_id_observed"`
	TransportCompleted bool   `json:"transport_completed"`
	Body               []byte `json:"body"`
}

func (nativeHCloudOriginal) String() string   { return "[private HCloud original return]" }
func (nativeHCloudOriginal) GoString() string { return "[private HCloud original return]" }

// Native provider JSON is extensible, but every identity key must be canonical
// and duplicate/case-folded aliases must be refused before struct decoding.
// This parser never promotes unknown provider metadata into public evidence.
func decodeNativeHCloudAPI(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 736<<10 {
		return errNativePhysical
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tokens := 0
	var walk func(int) error
	walk = func(depth int) error {
		tokens++
		if depth > 32 || tokens > 100000 {
			return errNativePhysical
		}
		token, err := d.Token()
		if err != nil {
			return errNativePhysical
		}
		if delimiter, ok := token.(json.Delim); ok {
			if delimiter != '{' && delimiter != '[' {
				return errNativePhysical
			}
			seen := map[string]bool{}
			for d.More() {
				if delimiter == '{' {
					key, err := d.Token()
					s, ok := key.(string)
					if err != nil || !ok || !nativeHCloudASCIIKey(s) || seen[s] {
						return errNativePhysical
					}
					seen[s] = true
				}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			if _, err = d.Token(); err != nil {
				return errNativePhysical
			}
		}
		return nil
	}
	if walk(0) != nil {
		return errNativePhysical
	}
	if _, err := d.Token(); err != io.EOF {
		return errNativePhysical
	}
	if json.Unmarshal(raw, out) != nil {
		return errNativePhysical
	}
	return nil
}

func nativeHCloudASCIIKey(s string) bool {
	if s == "" || len(s) > 512 {
		return false
	}
	for _, c := range s {
		if c < '!' || c > '~' || c >= 'A' && c <= 'Z' {
			return false
		}
	}
	return true
}

func nativeHCloudID(raw string) bool {
	id, err := strconv.ParseInt(raw, 10, 64)
	return err == nil && id > 0 && strconv.FormatInt(id, 10) == raw
}

func nativeHCloudSystemID(raw string) bool { return len(raw) <= 12 && nativeHCloudID(raw) }

func nativeHCloudRequestID(raw string, observed bool) bool {
	if !observed {
		return raw == ""
	}
	if len(raw) == 0 || len(raw) > 256 {
		return false
	}
	for _, c := range raw {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("._:-", c)) {
			return false
		}
	}
	return true
}

func nativeHCloudMAC(raw string) bool {
	m, err := net.ParseMAC(raw)
	return err == nil && len(m) == 6 && m.String() == raw && m[0]&1 == 0 && !bytes.Equal(m, make([]byte, 6))
}

func decodeNativeHCloudAcceptance(a model.CapacityNativeWorkerAttempt, original model.CapacityNativeWorkerOriginalReturn) (model.CapacityNativeWorkerHCloudAcceptance, error) {
	var out model.CapacityNativeWorkerHCloudAcceptance
	var wire nativeHCloudOriginal
	if a.Provider != "hetzner" || !original.CaptureComplete || original.ErrorClass != "" || len(original.Wire) == 0 || len(original.Wire) > 1<<20 ||
		DecodeNativeCapacity(json.RawMessage(original.Wire), &wire) != nil || wire.Schema != nativeHCloudOriginalSchema ||
		wire.AttemptID != a.ID.String() || wire.HTTPStatus != 201 || !wire.TransportCompleted || !nativeHCloudRequestID(wire.RequestID, wire.RequestIDObserved) {
		return out, errNativePhysical
	}
	var body struct {
		Server struct {
			ID         int64             `json:"id"`
			Name       string            `json:"name"`
			Created    time.Time         `json:"created"`
			Labels     map[string]string `json:"labels"`
			ServerType struct {
				ID   int64  `json:"id"`
				Name string `json:"name"`
			} `json:"server_type"`
			Image *struct {
				ID int64 `json:"id"`
			} `json:"image"`
			Location struct {
				ID          int64  `json:"id"`
				Name        string `json:"name"`
				NetworkZone string `json:"network_zone"`
			} `json:"location"`
			PrivateNet []struct {
				Network    int64    `json:"network"`
				IP         string   `json:"ip"`
				MACAddress string   `json:"mac_address"`
				AliasIPs   []string `json:"alias_ips"`
			} `json:"private_net"`
		} `json:"server"`
		Action struct {
			ID        int64           `json:"id"`
			Command   string          `json:"command"`
			Status    string          `json:"status"`
			Error     json.RawMessage `json:"error"`
			Resources []struct {
				ID   int64  `json:"id"`
				Type string `json:"type"`
			} `json:"resources"`
		} `json:"action"`
	}
	if decodeNativeHCloudAPI(wire.Body, &body) != nil {
		return out, errNativePhysical
	}
	s, action := body.Server, body.Action
	if s.ID < 1 || s.Name != "nw-"+strings.ReplaceAll(a.ID.String(), "-", "") || s.Created.IsZero() || s.ServerType.ID < 1 ||
		!marketID.MatchString(s.ServerType.Name) || s.Image == nil || s.Image.ID < 1 || s.Location.ID < 1 ||
		!marketID.MatchString(s.Location.Name) || !marketID.MatchString(s.Location.NetworkZone) ||
		action.ID < 1 || action.Command != "create_server" || action.Status != "running" && action.Status != "success" ||
		(len(action.Error) != 0 && string(action.Error) != "null") || len(action.Resources) > 16 || len(s.PrivateNet) > 1 {
		return out, errNativePhysical
	}
	for _, resource := range action.Resources {
		if resource.ID < 1 || resource.Type == "server" && resource.ID != s.ID {
			return out, errNativePhysical
		}
	}
	out = model.CapacityNativeWorkerHCloudAcceptance{
		ResourceID: strconv.FormatInt(s.ID, 10), ServerName: s.Name, CreatedAt: s.Created,
		ServerTypeID: strconv.FormatInt(s.ServerType.ID, 10), InstanceType: s.ServerType.Name,
		ImageID: strconv.FormatInt(s.Image.ID, 10), LocationID: strconv.FormatInt(s.Location.ID, 10),
		Location: s.Location.Name, NetworkZone: s.Location.NetworkZone,
		Labels: model.CapacityNativeWorkerHCloudObservedLabels{
			AttemptID: s.Labels["yggdrasil.io/native-worker-attempt"], PoolUID: s.Labels["dakasa.io/native-worker-pool"],
			LaunchSHA256Base32: s.Labels["yggdrasil.io/native-worker-launch-sha256"]},
		ActionID: strconv.FormatInt(action.ID, 10), ActionCommand: action.Command, ActionStatus: action.Status,
		RequestID: wire.RequestID, RequestIDObserved: wire.RequestIDObserved,
	}
	if len(s.PrivateNet) == 1 {
		n := s.PrivateNet[0]
		if n.Network < 1 || len(n.AliasIPs) != 0 {
			return model.CapacityNativeWorkerHCloudAcceptance{}, errNativePhysical
		}
		out.NetworkID, out.NativeIPv4, out.MACAddress = strconv.FormatInt(n.Network, 10), n.IP, n.MACAddress
		if n.IP != "" {
			ip, err := netip.ParseAddr(n.IP)
			if err != nil || !ip.Is4() || !ip.IsPrivate() || ip.String() != n.IP {
				return model.CapacityNativeWorkerHCloudAcceptance{}, errNativePhysical
			}
		}
		if n.MACAddress != "" && !nativeHCloudMAC(n.MACAddress) {
			return model.CapacityNativeWorkerHCloudAcceptance{}, errNativePhysical
		}
	}
	if !nativeHCloudSystemID(out.ResourceID) || !nativeHCloudSystemID(out.ImageID) {
		return model.CapacityNativeWorkerHCloudAcceptance{}, errNativePhysical
	}
	return out, nil
}
