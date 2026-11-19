"""SCOF finding enrichment and catalogue lookup.

Only the shared SCOF core should call this module. Consumers must not
independently parse policy messages or reproduce catalogue enrichment.

The raw violation string is preserved exactly in the ``violation`` field.
Unknown policy prefixes and known IDs without catalogue entries fail closed
with ``UNKNOWN``. Catalogue read/parse/structure failures return
``CATALOGUE_ERROR`` rather than silently passing.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
from typing import Any

_DEFAULT_CATALOGUE_PATH = (
    pathlib.Path(__file__).resolve().parent.parent.parent
    / "docs"
    / "regulation-mapping"
    / "control_catalogue.json"
)
_CATALOGUE_ENV = "SCOF_CONTROL_CATALOGUE"
_DEFAULT_REGISTRY_PATH = pathlib.Path(__file__).resolve().with_name("policy_message_registry.json")
_REGISTRY_ENV = "SCOF_POLICY_MESSAGE_REGISTRY"


def _load_message_registry(path: pathlib.Path | str | None = None) -> list[dict[str, Any]]:
    """Load exact message templates derived from production Rego sprintf calls."""
    configured = os.environ.get(_REGISTRY_ENV)
    resolved = pathlib.Path(path) if path is not None else (
        pathlib.Path(configured).expanduser() if configured else _DEFAULT_REGISTRY_PATH
    )
    try:
        data = json.loads(resolved.read_text(encoding="utf-8"))
        templates = data.get("templates") if isinstance(data, dict) else None
        if not isinstance(templates, list):
            raise ValueError("registry must contain a templates list")
        for item in templates:
            if not isinstance(item, dict) or not isinstance(item.get("control_id"), str) or not isinstance(item.get("regex"), str):
                raise ValueError("each registry entry must contain control_id and regex strings")
            re.compile(item["regex"])
        return templates
    except (OSError, ValueError, TypeError, re.error) as exc:
        raise RuntimeError(f"scof_findings: cannot load valid policy message registry at {resolved}: {exc}") from exc


def _is_registered_message(message: str, control_id: str, entries=None) -> bool:
    if entries is None:
        try:
            entries = _load_message_registry()
        except RuntimeError:
            return False
    return any(
        item.get("control_id") == control_id and re.fullmatch(item["regex"], message) is not None
        for item in entries
    )

# Includes CONTROL-SET because control_set.rego can emit configuration
# findings. It is intentionally not one of the eight catalogue controls.
_KNOWN_CONTROL_IDS: frozenset[str] = frozenset(
    {
        "REGION-RESTRICTION",
        "DATA-ENCRYPTION",
        "KEY-OWNERSHIP",
        "KEY-ROTATION",
        "IAM-NO-WILDCARD-ADMIN",
        "LOG-RETENTION",
        "ACCESS-EXPOSURE",
        "BACKUP-RESILIENCE",
        "CONTROL-SET",
    }
)

_ENRICHMENT_FIELDS = (
    "basis_label",
    "sources",
    "legal_requirement",
    "scof_interpretation",
    "applicability",
    "limitations",
)


def _catalogue_path() -> pathlib.Path:
    """Resolve the catalogue path, allowing an environment override."""
    configured = os.environ.get(_CATALOGUE_ENV)
    return pathlib.Path(configured).expanduser() if configured else _DEFAULT_CATALOGUE_PATH


def _load_catalogue(path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Load and minimally validate the catalogue; raise RuntimeError on failure."""
    resolved = pathlib.Path(path) if path is not None else _catalogue_path()
    try:
        data = json.loads(resolved.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("controls"), dict):
            raise ValueError("catalogue must be an object containing a controls object")
        return data
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError(
            f"scof_findings: cannot load valid control catalogue at {resolved}: {exc}"
        ) from exc
    
def validate_configuration() -> None:
    """Validate required enrichment files, even when a lint run has no findings.

    Raises RuntimeError when the catalogue or exact-message registry is
    missing or invalid. This is a tooling/configuration failure, not a
    policy verdict.
    """
    _load_catalogue()
    _load_message_registry()

def _extract_control_id(violation_message: str) -> str | None:
    """Return the prefix before the first colon, or None for malformed input."""
    if not isinstance(violation_message, str):
        return None
    first_colon = violation_message.find(":")
    if first_colon < 1:
        return None
    return violation_message[:first_colon].strip() or None


def _unknown_result(violation_message: str, control_id: str | None) -> dict[str, Any]:
    return {
        "violation": violation_message,
        "control_id": control_id,
        "enrichment_status": "UNKNOWN",
    }


def enrich(
    violation_message: str,
    context: str,
    catalogue: dict[str, Any] | None = None,
    registry: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Enrich one finding while preserving its original violation string."""
    control_id = _extract_control_id(violation_message)
    result = _unknown_result(violation_message, control_id)

    if control_id not in _KNOWN_CONTROL_IDS:
        return result

    # A recognised prefix is not enough: only exact production Rego message
    # shapes may receive regulatory enrichment. This prevents fabricated or
    # stale text from being treated as a verified policy finding.
    if not _is_registered_message(violation_message, control_id, registry):
        return result

    if catalogue is None:
        try:
            catalogue = _load_catalogue()
        except RuntimeError as exc:
            result["enrichment_status"] = "CATALOGUE_ERROR"
            result["catalogue_error"] = str(exc)
            return result

    controls = catalogue.get("controls")
    if not isinstance(controls, dict):
        result["enrichment_status"] = "CATALOGUE_ERROR"
        result["catalogue_error"] = "catalogue controls entry is missing or invalid"
        return result

    control_entry = controls.get(control_id)
    if not isinstance(control_entry, dict):
        # Includes CONTROL-SET: registered message prefix, intentionally
        # absent from the eight-control regulatory catalogue.
        return result

    context_entries = control_entry.get("contexts", {})
    if not isinstance(context_entries, dict):
        result["enrichment_status"] = "CATALOGUE_ERROR"
        result["catalogue_error"] = f"invalid contexts object for {control_id}"
        return result

    context_entry = context_entries.get(context, control_entry)
    if not isinstance(context_entry, dict):
        result["enrichment_status"] = "CATALOGUE_ERROR"
        result["catalogue_error"] = f"invalid catalogue entry for {control_id}/{context}"
        return result

    result["enrichment_status"] = "OK"
    for field in _ENRICHMENT_FIELDS:
        value = context_entry.get(field, control_entry.get(field))
        if value is None:
            value = [] if field == "sources" else ""
        result[field] = value

    return result


def enrich_all(
    violations: list[str],
    context: str,
    catalogue: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Enrich violations in their original order, loading the catalogue once."""
    if catalogue is None:
        try:
            catalogue = _load_catalogue()
        except RuntimeError as exc:
            results = []
            for violation in violations:
                control_id = _extract_control_id(violation)
                item = _unknown_result(violation, control_id)
                if control_id in _KNOWN_CONTROL_IDS:
                    item["enrichment_status"] = "CATALOGUE_ERROR"
                    item["catalogue_error"] = str(exc)
                results.append(item)
            return results

    try:
        registry = _load_message_registry()  # once per run, not once per finding
    except RuntimeError:
        registry = []  # same outcome as a per-finding load failure: nothing is registered
    return [enrich(item, context, catalogue, registry) for item in violations]
