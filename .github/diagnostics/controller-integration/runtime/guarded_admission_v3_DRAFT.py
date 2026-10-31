"""Guarded BPF admission intentionally unavailable until verified integration."""
from drain_coordination_DRAFT import FenceError

def evaluate(_request, coordination):
    with coordination.admission_or_other_writer():
        # NFT alone cannot attest an active Guardian/BPF generation. Do not
        # authorize any deletion until the real independent witness exists.
        raise FenceError('GUARDED_BPF_ADMISSION_NOT_VALIDATED')
