package capacity

import "errors"

// The current VM slot ledger authorizes acquisition/destruction, not changing
// power while retaining the same resource. Do not reinterpret destroy as stop.
var ErrPowerLifecycleUnqualified = errors.New("EC2 power lifecycle is not qualified by the VM slot mutation ledger")
