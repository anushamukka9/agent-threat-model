# Publishing

How a release of agent-threat-model gets to PyPI.

## The pipeline

The `Publish to PyPI` workflow in `.github/workflows/publish.yml`
builds the sdist and wheel, checks them with twine, and publishes
through PyPI trusted publishing. No API tokens are stored in the
repo.

- A published GitHub Release publishes to real PyPI:
  https://pypi.org/p/agent-threat-model
- A manual workflow run is a dry run and goes to TestPyPI only:
  https://test.pypi.org/p/agent-threat-model

## Before a release

1. Bump `version` in `pyproject.toml` and `__version__` in
   `src/agent_threat_model/__init__.py`. The packaging tests fail
   if they disagree.
2. Run the gates locally: `pytest`, `ruff check src tests`,
   `ruff format --check src tests`, and
   `python -m agent_threat_model.benchmark`. All must pass.
3. Build locally once: `python -m build` and `twine check dist/*`.
4. Tag and publish the GitHub Release. The workflow does the rest.

## Package facts

- Project name: `agent-threat-model`
- Import package: `agent_threat_model`
- Console script: `agent-threat-model`
- Build backend: hatchling, `src/` layout
- Runtime dependencies: none. The core is stdlib only.
