"""JSON export and import round-trips.

The plan slice for Nov 15: export a finished model to JSON, import
it back into the Python engine and the canvas, and get identical
results. Identical means byte-for-byte on the markdown output, for
both bundled example models.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from agent_threat_model import Architecture, ThreatModel, build_threat_model
from agent_threat_model.cli import main
from agent_threat_model.models import SpecError

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
EXAMPLE_FILES = ["support_agent.json", "hardened_agent.json"]


def _model(filename: str) -> ThreatModel:
    return build_threat_model(Architecture.from_json_file(EXAMPLES / filename))


@pytest.mark.parametrize("filename", EXAMPLE_FILES)
def test_spec_round_trip_markdown_byte_for_byte(filename):
    arch = Architecture.from_json_file(EXAMPLES / filename)
    original = build_threat_model(arch).to_markdown()
    rebuilt = Architecture.from_dict(arch.to_dict())
    assert build_threat_model(rebuilt).to_markdown() == original
    via_json = Architecture.from_json(arch.to_json())
    assert build_threat_model(via_json).to_markdown() == original
    assert via_json.to_dict() == arch.to_dict()


@pytest.mark.parametrize("filename", EXAMPLE_FILES)
def test_model_round_trip_markdown_byte_for_byte(filename):
    model = _model(filename)
    imported = ThreatModel.from_json(model.to_json())
    assert imported.to_markdown() == model.to_markdown()
    assert imported.to_json() == model.to_json()
    assert imported.to_dict() == model.to_dict()
    assert imported.summary_line() == model.summary_line()


@pytest.mark.parametrize("filename", EXAMPLE_FILES)
def test_model_round_trip_from_dict(filename):
    model = _model(filename)
    imported = ThreatModel.from_dict(json.loads(model.to_json()))
    assert imported.to_markdown() == model.to_markdown()
    # The spec rides along, canonicalized, so the canvas can rebuild
    # the same questionnaire state.
    assert imported.source_spec == model.source_spec
    assert imported.source_spec["name"] == model.architecture_name


def test_model_import_keeps_exported_threats_not_recomputed():
    model = _model("support_agent.json")
    data = json.loads(model.to_json())
    data["threats"] = data["threats"][:1]
    imported = ThreatModel.from_dict(data)
    assert len(imported.threats) == 1
    assert imported.threats[0].id == "ATM-012"


def test_model_import_rejects_bad_exports():
    with pytest.raises(SpecError):
        ThreatModel.from_json("{not json")
    with pytest.raises(SpecError):
        ThreatModel.from_dict({"architecture": "x"})
    with pytest.raises(SpecError):
        ThreatModel.from_dict(["not", "a", "dict"])
    with pytest.raises(SpecError):
        ThreatModel.from_json_file(ROOT / "examples" / "nope.json")


@pytest.mark.parametrize("filename", EXAMPLE_FILES)
def test_cli_export_import_round_trip(tmp_path, capsys, filename):
    spec_path = str(EXAMPLES / filename)
    model_path = tmp_path / "model.json"
    assert main(["export", spec_path, "--output", str(model_path)]) == 0
    capsys.readouterr()
    original = _model(filename)
    exported = json.loads(model_path.read_text(encoding="utf-8"))
    assert exported["architecture"] == original.architecture_name
    assert "spec" in exported

    expected_exit = (
        1
        if original.threats and any(t.severity in ("critical", "high") for t in original.threats)
        else 0
    )
    assert main(["import", str(model_path)]) == expected_exit
    assert capsys.readouterr().out == original.to_markdown() + "\n"

    assert main(["import", str(model_path), "--format", "json"]) == expected_exit
    assert capsys.readouterr().out == original.to_json()


def test_cli_import_bad_model_exits_2(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"architecture": "x"}', encoding="utf-8")
    assert main(["import", str(bad)]) == 2
    assert "error:" in capsys.readouterr().err


NODE_ROUNDTRIP = """
const fs = require("fs");
const path = require("path");
const root = process.argv[2];
const ATM = require(path.join(root, "canvas", "engine.js"));
for (const file of ["support_agent.json", "hardened_agent.json"]) {
  const spec = JSON.parse(
    fs.readFileSync(path.join(root, "examples", file), "utf8")
  );
  const model = ATM.buildThreatModel(spec);
  const exported = model.toJson();
  const imported = ATM.modelFromJson(exported);
  if (imported.toMarkdown() !== model.toMarkdown()) {
    throw new Error(file + ": markdown drift after model round-trip");
  }
  if (imported.toJson() !== exported) {
    throw new Error(file + ": JSON drift after model round-trip");
  }
  if (!imported.spec || imported.spec.name !== spec.name) {
    throw new Error(file + ": spec did not ride along in the export");
  }
  const viaSpec = ATM.buildThreatModel(imported.spec);
  if (viaSpec.toMarkdown() !== model.toMarkdown()) {
    throw new Error(file + ": markdown drift after spec round-trip");
  }
}
console.log("canvas round-trip ok");
"""


def test_canvas_model_round_trip_byte_for_byte(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not available")
    harness = tmp_path / "roundtrip.js"
    harness.write_text(NODE_ROUNDTRIP, encoding="utf-8")
    result = subprocess.run(
        [node, str(harness), str(ROOT)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "canvas round-trip ok" in result.stdout


def test_canvas_index_has_model_json_controls():
    text = (ROOT / "canvas" / "index.html").read_text(encoding="utf-8")
    assert 'id="export-model-json"' in text
    assert 'id="download-model-json"' in text
    assert 'id="load-model-json"' in text
    assert 'id="model-json"' in text


def test_cross_engine_model_import(tmp_path):
    """A model exported by Python imports in the canvas engine, and
    a model exported by the canvas imports in Python, both with
    byte-for-byte identical markdown."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not available")
    model = _model("support_agent.json")
    exported = tmp_path / "python-model.json"
    exported.write_text(model.to_json(), encoding="utf-8")

    harness = tmp_path / "cross.js"
    harness.write_text(
        """
const fs = require("fs");
const path = require("path");
const ATM = require(path.join(process.argv[2], "canvas", "engine.js"));
const imported = ATM.modelFromJson(fs.readFileSync(process.argv[3], "utf8"));
process.stdout.write(imported.toMarkdown());
const spec = JSON.parse(fs.readFileSync(
  path.join(process.argv[2], "examples", "hardened_agent.json"), "utf8"));
process.stdout.write("\\n---CANVAS-EXPORT---\\n");
process.stdout.write(ATM.buildThreatModel(spec).toJson());
""",
        encoding="utf-8",
    )
    result = subprocess.run(
        [node, str(harness), str(ROOT), str(exported)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    canvas_markdown, canvas_export = result.stdout.split("\n---CANVAS-EXPORT---\n", 1)
    assert canvas_markdown == model.to_markdown()
    hardened = _model("hardened_agent.json")
    imported = ThreatModel.from_json(canvas_export)
    assert imported.to_markdown() == hardened.to_markdown()
