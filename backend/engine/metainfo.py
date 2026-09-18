"""Single source of truth for the product/project version.

Every consumer (FastAPI metadata, validation reports, README-facing docs,
frontend cache-buster) must derive from this module so the version can never
drift across files again.
"""

PROJECT_VERSION = "0.3.0"
PROJECT_NAME = "NetProof"