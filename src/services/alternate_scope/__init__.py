"""Evidence-driven alternate scope and boundary proof rail."""

from .core import (
    build_alternate_scope_model_packet,
    inspect_alternate_scope_run,
    load_alternate_scope_bundle,
    resume_alternate_scope_run,
    run_alternate_scope_proof,
    validate_model_actions,
    verify_alternate_scope_run,
)
from .materialize import materialize_gemma_scope_candidate

__all__ = [
    "inspect_alternate_scope_run",
    "build_alternate_scope_model_packet",
    "load_alternate_scope_bundle",
    "resume_alternate_scope_run",
    "run_alternate_scope_proof",
    "validate_model_actions",
    "verify_alternate_scope_run",
    "materialize_gemma_scope_candidate",
]
