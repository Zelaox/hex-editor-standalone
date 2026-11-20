"""Verified, configuration-driven parser-learning feedback rail."""

from .core import (
    build_gemma_packet,
    build_gemma_prompt,
    compile_parser_candidates,
    load_parser_learning_bundle,
    parse_gemma_model_content,
    promote_profile_transaction,
    run_parser_learning,
    validate_candidates,
    validate_gemma_actions,
)
from .validation_runner import run_validation_checks

__all__ = [
    "build_gemma_packet",
    "build_gemma_prompt",
    "compile_parser_candidates",
    "load_parser_learning_bundle",
    "parse_gemma_model_content",
    "promote_profile_transaction",
    "run_parser_learning",
    "run_validation_checks",
    "validate_candidates",
    "validate_gemma_actions",
]
