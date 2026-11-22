"""Metadatos del proyecto: extra `dev` y workflow de CI coherentes.

La documentación manda ejecutar `pip install -e ".[dev]"` y el workflow hace lo
mismo; si el extra desaparece, CI seguiría pasando en local y fallaría en
GitHub. Este test lo fija.
"""
from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parent.parent
WORKFLOW = RAIZ / ".github" / "workflows" / "tests.yml"


def _pyproject() -> dict:
    with (RAIZ / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)


def test_dev_extra_installs_pytest():
    extras = _pyproject()["project"]["optional-dependencies"]
    assert "dev" in extras
    assert any(dep.split(">=")[0].strip() == "pytest" for dep in extras["dev"])


def test_runtime_dependencies_are_declared():
    deps = " ".join(_pyproject()["project"]["dependencies"]).lower()
    for paquete in ("pyyaml", "flask", "requests", "defusedxml", "scapy"):
        assert paquete in deps


def test_workflow_is_valid_yaml_and_runs_pytest():
    datos = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert datos["jobs"]["pytest"]["runs-on"] == "ubuntu-latest"
    versiones = datos["jobs"]["pytest"]["strategy"]["matrix"]["python-version"]
    assert versiones == ["3.11", "3.12", "3.13"]
    pasos = " ".join(str(paso.get("run", "")) for paso in datos["jobs"]["pytest"]["steps"])
    assert 'pip install -e ".[dev]"' in pasos
    assert "pytest" in pasos


def test_docs_refer_to_the_same_dev_extra():
    for doc in ("README.md", "Batrade_CONTEXTO.md"):
        texto = (RAIZ / doc).read_text(encoding="utf-8")
        if "[dev]" in texto:
            assert 'pip install' in texto
