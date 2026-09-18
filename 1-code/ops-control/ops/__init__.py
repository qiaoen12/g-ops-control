"""The small, offline-safe OPS-002 control-plane foundation."""

__version__ = "0.1.0"

from .models import (  # noqa: F401
    MODEL_SCHEMAS,
    ModelError,
    canonical_digest,
    canonical_json_bytes,
    new_uuid,
    validate_model,
)

__all__ = [
    "MODEL_SCHEMAS",
    "ModelError",
    "canonical_digest",
    "canonical_json_bytes",
    "new_uuid",
    "validate_model",
]
