package capacity

// This private per-effect archive is bounded separately from every public
// selector/callback/RPC. It does not widen any of those transport limits.
func DecodeNativeWorkerMemberJournalJSON(raw []byte, out any) error {
	return decodeNativeProbeResourceJSONBound(raw, out, 8<<20)
}
