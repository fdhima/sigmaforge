from __future__ import annotations

import importlib
from typing import Optional

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

from app.schemas.sigma_rule import SigmaRuleCreate


class SigmaParseError(Exception):
    pass


class SigmaConversionError(Exception):
    pass


# Maps short backend names to (module_path, class_name).
# Install the corresponding pySigma-backend-* package to enable each entry.
_BACKEND_REGISTRY: dict[str, tuple[str, str]] = {
    "splunk":       ("sigma.backends.splunk",               "SplunkBackend"),
    "lucene":       ("sigma.backends.elasticsearch",        "LuceneBackend"),
    "eql":          ("sigma.backends.elasticsearch",        "EQLBackend"),
    "opensearch":   ("sigma.backends.opensearch",           "OpensearchLuceneBackend"),
    "qradar":       ("sigma.backends.qradar",               "QRadarBackend"),
    "microsoft365": ("sigma.backends.microsoft365defender", "Microsoft365DefenderBackend"),
    "sqlite":       ("sigma.backends.sqlite",               "sqliteBackend"),
}


# ---------------------------------------------------------------------------
# Step 1 — YAML → SigmaCollection
# ---------------------------------------------------------------------------

def load_collection(raw_yaml: str) -> SigmaCollection:
    """Parse a raw Sigma YAML string into a pySigma SigmaCollection."""
    try:
        return SigmaCollection.from_yaml(raw_yaml)
    except SigmaError as e:
        raise SigmaParseError(f"Invalid Sigma rule: {e}") from e
    except yaml.YAMLError as e:
        raise SigmaParseError(f"YAML parse error: {e}") from e


# ---------------------------------------------------------------------------
# Step 2 — SigmaCollection → SigmaRuleCreate (for DB persistence)
# ---------------------------------------------------------------------------

def collection_to_schema(collection: SigmaCollection, raw_yaml: str) -> SigmaRuleCreate:
    """Map the first rule in a SigmaCollection to a SigmaRuleCreate schema."""
    if not collection:
        raise SigmaParseError("No rules found in the provided YAML")

    rule = collection[0]
    ls = rule.logsource
    raw_dict = yaml.safe_load(raw_yaml)

    return SigmaRuleCreate(
        id=rule.id,
        title=rule.title,
        status=rule.status.name if rule.status else None,
        description=rule.description,
        license=rule.license,
        author=rule.author,
        date=rule.date,
        modified=rule.modified,
        references=list(rule.references) if rule.references else None,
        tags=[str(t) for t in rule.tags] if rule.tags else None,
        falsepositives=list(rule.falsepositives) if rule.falsepositives else None,
        level=rule.level.name if rule.level else None,
        logsource_category=ls.category,
        logsource_product=ls.product,
        logsource_service=ls.service,
        logsource_definition=ls.definition,
        detection=raw_dict.get("detection", {}),
        raw_rule=raw_yaml,
    )


def parse_sigma_yaml(raw_yaml: str) -> SigmaRuleCreate:
    """Convenience wrapper: YAML string → SigmaRuleCreate in one call."""
    collection = load_collection(raw_yaml)
    return collection_to_schema(collection, raw_yaml)


# ---------------------------------------------------------------------------
# Step 3 — SigmaCollection → query strings via a backend
# ---------------------------------------------------------------------------

def convert_collection(
    collection: SigmaCollection,
    backend_name: str,
    pipeline_names: Optional[list[str]] = None,
) -> list[str]:
    """Convert a SigmaCollection to backend-specific query strings."""
    backend_cls = _resolve_backend(backend_name)

    pipeline = None
    if pipeline_names:
        from sigma.processing.resolver import ProcessingPipelineResolver
        resolver = ProcessingPipelineResolver()
        pipeline = resolver.resolve(pipeline_names)

    try:
        backend = backend_cls(processing_pipeline=pipeline)
        return backend.convert(collection)
    except Exception as e:
        raise SigmaConversionError(f"Conversion to '{backend_name}' failed: {e}") from e


def convert_to_query(
    raw_yaml: str,
    backend_name: str,
    pipeline_names: Optional[list[str]] = None,
) -> list[str]:
    """Convenience wrapper: YAML string → query strings in one call."""
    collection = load_collection(raw_yaml)
    return convert_collection(collection, backend_name, pipeline_names)


def list_backends() -> list[str]:
    return list(_BACKEND_REGISTRY.keys())


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resolve_backend(name: str):
    if name not in _BACKEND_REGISTRY:
        raise SigmaConversionError(
            f"Unknown backend '{name}'. Available: {', '.join(_BACKEND_REGISTRY)}"
        )
    module_path, class_name = _BACKEND_REGISTRY[name]
    try:
        module = importlib.import_module(module_path)
        return getattr(module, class_name)
    except ImportError as e:
        raise SigmaConversionError(
            f"Backend '{name}' is not installed. "
            f"Run: pip install pySigma-backend-{name}"
        ) from e
