"""Canvas tests: files, rule coverage, no em-dashes, JS parity."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANVAS = ROOT / "canvas"
EM_DASH = "\u2014"

RULE_IDS = [f"ATM-{n:03d}" for n in range(1, 24)]

NODE_HARNESS = """
const fs = require("fs");
const path = require("path");
const root = process.argv[2];
const ATM = require(path.join(root, "canvas", "engine.js"));
function sortedIds(model) {
  return model.threats.map(function (t) { return t.id; }).sort();
}
function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}
const cases = JSON.parse(
  fs.readFileSync(path.join(root, "benchmarks", "cases.json"), "utf8")
).cases;
for (const c of cases) {
  const got = sortedIds(ATM.buildThreatModel(c.spec));
  const want = c.expected_threat_ids.slice().sort();
  if (!same(got, want)) {
    throw new Error(c.name + ": got " + got.join(",") + " want " + want.join(","));
  }
}
const support = JSON.parse(
  fs.readFileSync(path.join(root, "examples", "support_agent.json"), "utf8")
);
const supportModel = ATM.buildThreatModel(support);
const expectedSummary =
  "19 threats: 1 critical, 11 high, 6 medium, 1 low; overall score 6/100";
if (supportModel.summaryLine() !== expectedSummary) {
  throw new Error("support summary: " + supportModel.summaryLine());
}
const hardened = JSON.parse(
  fs.readFileSync(path.join(root, "examples", "hardened_agent.json"), "utf8")
);
const hardenedModel = ATM.buildThreatModel(hardened);
if (hardenedModel.threats.length !== 0 || hardenedModel.scorecard.overall !== 100) {
  throw new Error(
    "hardened: " + hardenedModel.threats.length + " threats, score " +
      hardenedModel.scorecard.overall
  );
}
console.log("parity ok: " + cases.length + " cases");
"""


def test_canvas_files_exist():
    assert (CANVAS / "index.html").is_file()
    assert (CANVAS / "engine.js").is_file()
    assert (CANVAS / "README.md").is_file()
    assert (ROOT / "docs" / "canvas.md").is_file()


def test_engine_js_has_all_rule_ids():
    text = (CANVAS / "engine.js").read_text(encoding="utf-8")
    for rule_id in RULE_IDS:
        assert rule_id in text, f"{rule_id} missing from engine.js"


def test_index_html_references_engine_and_controls():
    text = (CANVAS / "index.html").read_text(encoding="utf-8")
    assert "engine.js" in text
    assert 'id="export-markdown"' in text
    assert 'id="copy-markdown"' in text
    assert 'id="share-link"' in text
    assert "Export to markdown" in text
    assert "Share link" in text


def test_no_em_dash_in_canvas_files():
    paths = [
        CANVAS / "index.html",
        CANVAS / "engine.js",
        CANVAS / "README.md",
        ROOT / "docs" / "canvas.md",
    ]
    for path in paths:
        assert EM_DASH not in path.read_text(encoding="utf-8"), f"em-dash in {path}"


def test_node_parity_with_python_engine(tmp_path):
    node = shutil.which("node")
    if node is None:
        import pytest

        pytest.skip("node is not available")
    harness = tmp_path / "parity.js"
    harness.write_text(NODE_HARNESS, encoding="utf-8")
    result = subprocess.run(
        [node, str(harness), str(ROOT)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "parity ok" in result.stdout
    cases = json.loads((ROOT / "benchmarks" / "cases.json").read_text(encoding="utf-8"))
    assert len(cases["cases"]) == 8
