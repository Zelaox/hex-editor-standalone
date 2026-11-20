"""Coverage-complete full-file decode and ASCII export."""

from .ascii_codec import decode_lossless_ascii, encode_lossless_ascii
from .core import (
    apply_full_decode_advisory_action,
    build_full_decode_model_packet,
    execute_registered_measurements,
    inspect_full_decode_run,
    resume_full_decode_run,
    run_full_decode_e2e,
    validate_full_decode_model_action,
    verify_full_decode_run,
)

__all__ = [
    "decode_lossless_ascii",
    "encode_lossless_ascii",
    "apply_full_decode_advisory_action",
    "build_full_decode_model_packet",
    "execute_registered_measurements",
    "inspect_full_decode_run",
    "resume_full_decode_run",
    "run_full_decode_e2e",
    "validate_full_decode_model_action",
    "verify_full_decode_run",
]
