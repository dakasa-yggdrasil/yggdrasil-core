package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProjectionObserverRejectsForeignHostAndObjectSelectors(t *testing.T) {
	image := "docker.io/library/native-probe-service@sha256:" + strings.Repeat("a", 64)
	if !imageName.MatchString(image) {
		t.Fatal("exact immutable image rejected")
	}
	for _, foreign := range []string{
		strings.Replace(image, "docker.io", "dockerXio", 1),
		strings.Replace(image, "docker.io", "docker-io", 1),
		"foreign." + image,
		strings.Replace(image, "docker.io", "DOCKER.IO", 1),
		strings.Replace(image, "@sha256:", ":tag@sha256:", 1),
		image + "a",
		image + "\n",
	} {
		if imageName.MatchString(foreign) {
			t.Fatal("foreign image could start the host metadata observer")
		}
	}
	var p pod
	raw := `{"metadata":{"name":"nps-234567892345-floor","uid":"12345678-1234-4234-8234-123456789abc","labels":{"yggdrasil.io/probe-service-ci-role":"floor","yggdrasil.io/probe-service-ci-run":"23456789-2345-4345-8345-23456789abcd"}},"spec":{"nodeName":"native-probe-service-worker","containers":[{"name":"probe","image":"` + image + `"}]}}`
	if json.Unmarshal([]byte(raw), &p) != nil || !ownedPod(p, image) {
		t.Fatal("exact disposable Pod selector rejected")
	}
	for _, fault := range []string{"node", "path_uid", "nil_uid", "name", "role", "run", "image", "extra_container", "command", "zero_run", "prefix"} {
		t.Run(fault, func(t *testing.T) {
			var x pod
			if json.Unmarshal([]byte(raw), &x) != nil {
				t.Fatal("fixture")
			}
			switch fault {
			case "node":
				x.Spec.NodeName = "floor-production"
			case "path_uid":
				x.Metadata.UID = "../../private"
			case "nil_uid":
				x.Metadata.UID = "00000000-0000-0000-0000-000000000000"
			case "name":
				x.Metadata.Name = "business-pod"
			case "role":
				x.Metadata.Labels["yggdrasil.io/probe-service-ci-role"] = "candidate"
			case "run":
				x.Metadata.Labels["yggdrasil.io/probe-service-ci-run"] = ""
			case "image":
				x.Spec.Containers[0].Image = "foreign:tag"
			case "extra_container":
				x.Spec.Containers = append(x.Spec.Containers, x.Spec.Containers[0])
			case "command":
				x.Spec.Containers[0].Command = []string{"foreign"}
			case "zero_run":
				x.Metadata.Labels["yggdrasil.io/probe-service-ci-run"] = "00000000-0000-0000-0000-000000000000"
			case "prefix":
				x.Metadata.Name = "nps-000000000000-floor"
			}
			if ownedPod(x, image) {
				t.Fatal("foreign object could select a host metadata path")
			}
		})
	}
}
func TestProjectionObserverBoundsChildOutputWithoutLeakingDiscardedBytes(t *testing.T) {
	b := &output{limit: 4}
	for _, s := range []string{"ab", "cdef", "private-overflow"} {
		n, err := b.Write([]byte(s))
		if err != nil || n != len(s) {
			t.Fatal("original child was not drained")
		}
	}
	if string(b.b) != "abcd" || !b.overflow {
		t.Fatal("bounded diagnostic output changed")
	}
}
