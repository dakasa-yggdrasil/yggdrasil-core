# Disposable Kubernetes Service qualification

`qualification_linux_test.go` in `internal/nativeprobeservicekind` is the Go
controller, built only with `linux && nativeprobeservicekind`. It is outside the
ordinary probe root glob and fails unless the dedicated GitHub Kind guards are
present. The workflow selects its one root exactly, retains original test JSON,
refuses skips, and verifies the public proof and artifact hashes.

The Dockerfile packages the exact amd64 binary already produced by the normal
image job. It adds no wrapper to the agent. The other target is only the tagged
Go test controller. Both images are loaded once, joined to the actual containerd
manifest/config on all disposable nodes, and used by immutable digest. The
normal agent's compiled Source, clean buildvcs and binary hash remain the source
of its identity; repackaging does not claim the two image digests are identical.

The controller creates two Pods on different actual workers, two ClusterIP UDP
Services and late immutable Secret material. It independently reads the native
Pod, Node, Service and EndpointSlice identities and their lifetimes. The agent's
normal 45-second optional-Secret wait is unchanged. No init container, command,
argument, utility waiter, host route, port-forward or kubelet cadence adjustment
makes that wait succeed. A projection or loader failure remains a qualification
failure, with safe process/Secret creation timing retained in original output.

Only the controller has a disposable namespaced service account. The agent has
no Kubernetes token or API authority. Bootstrap YAML declares the finite Kind
cluster, namespaced RBAC and one non-restarting controller Job. The Go controller
owns resource selection, key creation in memory, typed API joins, actual mTLS
calls, the four one-shot control POSTs and signed frame assertions. YAML and
shell do not generate probe packets or pretend that loopback is a Service.

The proof must contain a signed service-path echo received from the actual peer
ClusterIP, with all twelve requests and twelve echoes, actual source addresses,
and original process/object lifetimes unchanged. The normal agent may also
receive Pod-IP Service replies, but that alone cannot pass this particular NAT
case. Failed or unknown control calls are not replayed. Raw Secrets, private
keys, service-account tokens and kubeconfig are never logged or uploaded.

The test establishes the particular disposable Kind network path only. Run and
birth placeholders are explicitly synthetic, candidate startup is never called,
and birth/startup/readiness qualification flags are false. It does not qualify
Native workers, production Flannel, external MTU/warmup, traffic or admission.
