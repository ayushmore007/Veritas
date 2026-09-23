"""Smoke tests for Phase 0 scaffold."""

from pathlib import Path

import veritas


def test_package_imports():
    assert veritas.__version__ == "0.1.0"


def test_config_files_exist():
    root = Path(__file__).resolve().parents[1]
    assert (root / "config" / "default.yaml").is_file()
    assert (root / "config" / "trust_labels.yaml").is_file()


def test_docs_exist():
    root = Path(__file__).resolve().parents[1]
    assert (root / "docs" / "licensing-and-citation.md").is_file()
    assert (root / "docs" / "license-audit.md").is_file()
