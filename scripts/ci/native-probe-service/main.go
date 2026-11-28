// Command native-probe-service observes only disposable Kind projection metadata.
// It never delays/starts an agent or reads projected Secret file contents.
// Node configuration is reduced to the two public synchronization fields.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sigs.k8s.io/yaml"
)

const contextName = "kind-native-probe-service"
const namespace = "native-probe-service-ci"

var uuidText = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var podName = regexp.MustCompile(`^nps-[a-f0-9]{12}-(floor|candidate)$`)
var imageName = regexp.MustCompile(`^docker\.io/library/native-probe-service@sha256:[a-f0-9]{64}$`)
var files = []string{"config.json", "server.crt", "server.key", "controller-ca.crt", "signing.key", "peer-signing.pub", "admission.key"}

type pod struct {
	Metadata struct {
		Name, UID string
		Labels    map[string]string
	}
	Spec struct {
		NodeName   string
		Containers []struct {
			Name, Image   string
			Command, Args []string
		}
	}
	Status struct {
		ContainerStatuses []struct {
			Name  string
			State struct {
				Running    *struct{ StartedAt time.Time }
				Terminated *struct {
					ExitCode              int
					StartedAt, FinishedAt time.Time
				}
			}
		}
	}
}
type fileFact struct {
	Name        string
	Present     *bool
	BytesLength *int64
	State       string
}
type kubeletFact struct {
	SyncFrequency  string `json:"syncFrequency"`
	SecretStrategy string `json:"configMapAndSecretChangeDetectionStrategy"`
	Complete       bool
}
type observation struct {
	Schema                    string
	ObservedAt                time.Time
	PodName, PodUID, NodeName string
	StartedAt, FinishedAt     time.Time
	ExitCode                  *int
	Kubelet                   kubeletFact
	Files                     []fileFact
}
type output struct {
	b        []byte
	limit    int
	overflow bool
}

func (o *output) Write(b []byte) (int, error) {
	n := len(b)
	left := o.limit - len(o.b)
	if n > left {
		o.b = append(o.b, b[:left]...)
		o.overflow = true
	} else {
		o.b = append(o.b, b...)
	}
	return n, nil
}

func run(parent context.Context, name string, args ...string) ([]byte, []byte, bool, bool) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.WaitDelay = time.Second
	out, errout := &output{limit: 256 << 10}, &output{limit: 16 << 10}
	c.Stdout, c.Stderr = out, errout
	err := c.Run()
	complete := ctx.Err() == nil && !out.overflow && !errout.overflow && !errors.Is(err, exec.ErrWaitDelay)
	// Nonzero stat from a missing path is represented in its original stderr;
	// no other error or a truncated/canceled read is treated as absence.
	return out.b, errout.b, complete, err == nil
}
func config(ctx context.Context, node string) kubeletFact {
	raw, _, complete, ok := run(ctx, "docker", "exec", node, "cat", "/var/lib/kubelet/config.yaml")
	defer clear(raw)
	var f kubeletFact
	if !complete || !ok || yaml.Unmarshal(raw, &f) != nil || len(f.SyncFrequency) > 32 || len(f.SecretStrategy) > 32 {
		return kubeletFact{}
	}
	if _, err := time.ParseDuration(f.SyncFrequency); err != nil {
		return kubeletFact{}
	}
	if f.SecretStrategy != "Watch" && f.SecretStrategy != "Cache" && f.SecretStrategy != "Get" {
		return kubeletFact{}
	}
	f.Complete = true
	return f
}
func snapshot(ctx context.Context, p pod, k kubeletFact) observation {
	o := observation{Schema: "native_probe_projection_metadata_v1", PodName: p.Metadata.Name, PodUID: p.Metadata.UID, NodeName: p.Spec.NodeName, Kubelet: k}
	for _, c := range p.Status.ContainerStatuses {
		if c.Name != "probe" {
			continue
		}
		if c.State.Running != nil {
			o.StartedAt = c.State.Running.StartedAt
		}
		if c.State.Terminated != nil {
			x := c.State.Terminated
			o.StartedAt, o.FinishedAt, o.ExitCode = x.StartedAt, x.FinishedAt, &x.ExitCode
		}
	}
	base := "/var/lib/kubelet/pods/" + p.Metadata.UID + "/volumes/kubernetes.io~secret/material"
	args := []string{"exec", "--env", "LC_ALL=C", p.Spec.NodeName, "stat", "-L", "--printf=%n\t%s\n", "--"}
	byPath := map[string]int{}
	for _, f := range files {
		path := filepath.Join(base, f)
		byPath[path] = len(o.Files)
		o.Files = append(o.Files, fileFact{Name: f, State: "unknown"})
		args = append(args, path)
	}
	stdout, stderr, complete, _ := run(ctx, "docker", args...)
	if !complete {
		o.ObservedAt = time.Now().UTC()
		return o
	}
	for _, line := range strings.Split(string(stdout), "\n") {
		a := strings.Split(line, "\t")
		if len(a) != 2 {
			continue
		}
		i, ok := byPath[a[0]]
		if !ok {
			continue
		}
		size, e := strconv.ParseInt(a[1], 10, 64)
		if e != nil || size < 0 {
			continue
		}
		yes := true
		o.Files[i] = fileFact{Name: o.Files[i].Name, Present: &yes, BytesLength: &size, State: "metadata_observed"}
	}
	// Truncated/canceled/pipe-close reads returned unknown above. With complete
	// original stat output, every emitted row is real metadata. Explicit GNU
	// ENOENT rows may identify a
	// missing fixed file; permission/transport errors are never normalized to it.
	if len(stderr) < 16<<10 && len(stdout) < 256<<10 && ctx.Err() == nil {
		for _, line := range strings.Split(string(stderr), "\n") {
			for path, i := range byPath {
				if strings.Contains(line, "'"+path+"'") && strings.HasSuffix(line, ": No such file or directory") {
					no := false
					o.Files[i] = fileFact{Name: o.Files[i].Name, Present: &no, State: "not_found"}
				}
			}
		}
	}
	// Date the metadata after its original read, never before a potentially
	// delayed stat. This timestamp cannot predate a later observed projection.
	o.ObservedAt = time.Now().UTC()
	return o
}
func main() {
	image := os.Getenv("NATIVE_PROBE_SERVICE_IMAGE")
	if len(os.Args) != 1 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("REQUIRE_NATIVE_PROBE_SERVICE_KIND") != "true" || !imageName.MatchString(image) {
		os.Exit(1)
	}
	parent, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, 270*time.Second)
	defer cancel()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	remaining := 128 << 10
	seen := map[string]string{}
	configs := map[string]kubeletFact{}
	for {
		raw, _, complete, ok := run(ctx, "kubectl", "--context", contextName, "-n", namespace, "get", "pods", "-l", "yggdrasil.io/probe-service-ci-role", "-o", "json")
		var list struct{ Items []pod }
		if complete && ok && json.Unmarshal(raw, &list) == nil && len(list.Items) <= 2 {
			for _, p := range list.Items {
				if !ownedPod(p, image) {
					continue
				}
				k := configs[p.Spec.NodeName]
				if !k.Complete {
					k = config(ctx, p.Spec.NodeName)
					if k.Complete {
						configs[p.Spec.NodeName] = k
					}
				}
				o := snapshot(ctx, p, k)
				state := o
				state.ObservedAt = time.Time{}
				b, _ := json.Marshal(state)
				if seen[p.Metadata.UID] != string(b) {
					seen[p.Metadata.UID] = string(b)
					wire, _ := json.Marshal(o)
					wire = append(wire, '\n')
					if len(wire) > remaining {
						return
					}
					remaining -= len(wire)
					if _, err := os.Stdout.Write(wire); err != nil {
						return
					}
				}
			}
		}
		clear(raw)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func ownedPod(p pod, image string) bool {
	role := p.Metadata.Labels["yggdrasil.io/probe-service-ci-role"]
	run := p.Metadata.Labels["yggdrasil.io/probe-service-ci-run"]
	if !uuidText.MatchString(run) || run == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	expectedName := "nps-" + strings.ReplaceAll(run, "-", "")[:12] + "-" + role
	return p.Metadata.Name == expectedName && podName.MatchString(p.Metadata.Name) && uuidText.MatchString(p.Metadata.UID) && p.Metadata.UID != "00000000-0000-0000-0000-000000000000" && uuidText.MatchString(p.Metadata.Labels["yggdrasil.io/probe-service-ci-run"]) && (role == "floor" || role == "candidate") && strings.HasSuffix(p.Metadata.Name, "-"+role) && len(p.Spec.Containers) == 1 && p.Spec.Containers[0].Name == "probe" && p.Spec.Containers[0].Image == image && len(p.Spec.Containers[0].Command) == 0 && len(p.Spec.Containers[0].Args) == 0 && (p.Spec.NodeName == "native-probe-service-worker" || p.Spec.NodeName == "native-probe-service-worker2")
}
