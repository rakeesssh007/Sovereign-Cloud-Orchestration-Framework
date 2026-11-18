import hashlib, json, sys
from pathlib import Path
path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs/regulation-mapping/control_catalogue.json")
data = json.loads(path.read_text(encoding="utf-8"))
meta = data.get("_meta", {})
expected = meta.get("content_hash", "")
if not expected.startswith("sha256:"):
    raise SystemExit("FAIL: _meta.content_hash is missing or not sha256-prefixed")
meta.pop("content_hash", None)
canonical = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
actual = "sha256:" + hashlib.sha256(canonical).hexdigest()
print(f"Catalogue version: {meta.get('version', 'UNKNOWN')}")
print(f"Expected: {expected}")
print(f"Actual:   {actual}")
if actual != expected:
    raise SystemExit("FAIL: catalogue content hash mismatch")
controls = data.get("controls", {})
if len(controls) != 8:
    raise SystemExit(f"FAIL: expected 8 controls, found {len(controls)}")
missing = []
for control_id, entry in controls.items():
    for node in [entry, *entry.get("contexts", {}).values()]:
        for source in node.get("source_mappings", []):
            if not source.get("legal_status"):
                missing.append((control_id, source.get("source_id")))
if missing:
    raise SystemExit(f"FAIL: source mappings missing legal_status: {missing}")
matrix_path = Path("docs/regulation-mapping/regulation_control_matrix.md")
if matrix_path.is_file():
    matrix = matrix_path.read_text(encoding="utf-8")
    import re
    for control_id, entry in controls.items():
        match = re.search(rf"(?m)^### {re.escape(control_id)}\s*$", matrix)
        if not match:
            raise SystemExit(f"FAIL: matrix section missing for {control_id}")
        next_heading = re.search(r"(?m)^#{2,3} ", matrix[match.end():])
        end = match.end() + next_heading.start() if next_heading else len(matrix)
        if entry.get("matrix_text") != matrix[match.start():end].rstrip("\n"):
            raise SystemExit(f"FAIL: matrix_text drift for {control_id}")
    print("PASS: exact matrix_text matches 8/8 controls")
print(f"PASS: 8 controls; all source mappings have legal_status; {actual}")
