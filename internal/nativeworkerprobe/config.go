package nativeworkerprobe

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var ErrUnavailable = errors.New("native worker diagnostic unavailable")

var (
	uuidPattern   = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	sourcePattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	namePattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
)

type material struct {
	config   Config
	scope    string
	server   tls.Certificate
	clientCA *x509.CertPool
	signing  ed25519.PrivateKey
	peer     ed25519.PublicKey
	startup  []byte
}

func (material) String() string   { return "[private native probe material]" }
func (material) GoString() string { return "[private native probe material]" }
func (material) MarshalJSON() ([]byte, error) {
	return []byte(`"[private native probe material]"`), nil
}

func (m *material) close() {
	if m == nil {
		return
	}
	wipe(m.signing)
	wipe(m.startup)
	if key, ok := m.server.PrivateKey.(ed25519.PrivateKey); ok {
		wipe(key)
	}
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func validUUID(s string) bool {
	return uuidPattern.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}

func canonicalIPv4(raw string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(raw)
	return a, err == nil && a.Is4() && a.String() == raw && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() && !a.IsLinkLocalUnicast()
}

func validConfig(c Config, source string, now time.Time) bool {
	i, p := c.Identity, c.Peer
	if c.Schema != ConfigSchema || !sourcePattern.MatchString(source) || c.SourceCommit != source || !validUUID(i.RunID) || !validUUID(i.AttemptID) || !digestPattern.MatchString(i.BirthSHA256) || !validUUID(i.PoolUID) || (i.Role != "floor" && i.Role != "candidate") || !namePattern.MatchString(i.Namespace) || !validUUID(i.NamespaceUID) || !namePattern.MatchString(i.PodName) || !validUUID(i.PodUID) || !namePattern.MatchString(i.NodeName) || !validUUID(i.NodeUID) || !validUUID(i.ServiceUID) || !validUUID(p.PodUID) || !validUUID(p.NodeUID) || !validUUID(p.ServiceUID) || i.PodUID == p.PodUID || i.NodeUID == p.NodeUID || i.ServiceUID == p.ServiceUID || !digestPattern.MatchString(c.ControllerLeafSHA256) || c.NotBefore.IsZero() || now.Before(c.NotBefore) || !c.HardNotAfter.After(now) || !c.HardNotAfter.After(c.NotBefore) {
		return false
	}
	nonce, err := base64.StdEncoding.DecodeString(c.Nonce)
	if err != nil || len(nonce) != 32 || base64.StdEncoding.EncodeToString(nonce) != c.Nonce {
		return false
	}
	pods, pe := netip.ParsePrefix(c.PodCIDR)
	services, se := netip.ParsePrefix(c.ServiceCIDR)
	if pe != nil || se != nil || !pods.Addr().Is4() || !services.Addr().Is4() || pods.Masked().String() != c.PodCIDR || services.Masked().String() != c.ServiceCIDR || pods.Overlaps(services) {
		return false
	}
	seen := map[netip.Addr]bool{}
	for _, row := range []struct {
		value string
		net   netip.Prefix
	}{{i.PodIPv4, pods}, {p.PodIPv4, pods}, {i.ServiceClusterIPv4, services}, {p.ServiceClusterIPv4, services}} {
		ip, valid := canonicalIPv4(row.value)
		if !valid || !row.net.Contains(ip) || seen[ip] {
			return false
		}
		seen[ip] = true
	}
	if i.Role == "floor" {
		return c.Startup == nil
	}
	s := c.Startup
	return s != nil && sourcePattern.MatchString(s.CoreSourceCommit) && strings.HasPrefix(s.ImageDigest, "sha256:") && digestPattern.MatchString(strings.TrimPrefix(s.ImageDigest, "sha256:")) && validUUID(s.WorkloadUID) && namePattern.MatchString(s.ContainerName) && digestPattern.MatchString(s.LaneRosterSHA256)
}

// Reject aliases/duplicates/null before encoding/json's field-name folding.
// Values remain ordinary Unicode JSON; only the closed protocol keys are ASCII.
func decodeClosed(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 24 {
			return ErrUnavailable
		}
		t, err := d.Token()
		if err != nil || t == nil {
			return ErrUnavailable
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, e := d.Token()
					s, ok := key.(string)
					if e != nil || !ok || s == "" || seen[s] {
						return ErrUnavailable
					}
					for _, ch := range s {
						if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_') {
							return ErrUnavailable
						}
					}
					seen[s] = true
					if walk(depth+1) != nil {
						return ErrUnavailable
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return ErrUnavailable
				}
			case '[':
				for d.More() {
					if walk(depth+1) != nil {
						return ErrUnavailable
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return ErrUnavailable
				}
			default:
				return ErrUnavailable
			}
		}
		return nil
	}
	if walk(0) != nil || d.Decode(new(any)) != io.EOF {
		return ErrUnavailable
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrUnavailable
	}
	return nil
}

func readSecret(dir, name string, limit int64) ([]byte, error) {
	path := filepath.Join(dir, name)
	entry, err := os.Lstat(path)
	if err != nil || !entry.Mode().IsRegular() {
		return nil, ErrUnavailable
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || !os.SameFile(entry, before) || before.Mode().Perm()&0037 != 0 || before.Size() < 1 || before.Size() > limit || !secretStatAllowed(before) {
		_ = f.Close()
		return nil, ErrUnavailable
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := f.Stat()
	closeErr := f.Close()
	last, entryErr := os.Lstat(path)
	if readErr != nil || statErr != nil || closeErr != nil || entryErr != nil || !last.Mode().IsRegular() || !os.SameFile(before, last) || !os.SameFile(before, after) || !secretStatEqual(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || int64(len(raw)) != before.Size() {
		wipe(raw)
		return nil, ErrUnavailable
	}
	return raw, nil
}
