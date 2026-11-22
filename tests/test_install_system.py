"""Instalación de sistema y resolución de raíz, sin tocar el sistema real.

Todo se ejecuta con `--dry-run` o contra prefijos temporales. El script admite
`BATRADE_TEST_FAKE_ROOT=1` para no exigir root en las pruebas; `BATRADE_BIN_DIR`
redirige el comando para no escribir nunca en /usr/local/bin.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from batrade import cli

REPO = Path(__file__).resolve().parent.parent
INSTALL = REPO / "install.sh"
SYNC = REPO / "scripts" / "sync_tree.sh"

CONFIG_MIN = """\
network:
  interface: lo
  cidr: 10.10.10.0/24
  gateway_ip: 10.10.10.1
sensor:
  mode: degraded
scan:
  enabled: false
detect:
  arp_verify: false
"""


def _run(args, *, fake_root=True, bin_dir=None, cwd=None, extra_env=None):
    env = {k: v for k, v in os.environ.items() if k != "BATRADE_ROOT"}
    env.pop("BATRADE_TEST_FAKE_ROOT", None)
    if fake_root:
        env["BATRADE_TEST_FAKE_ROOT"] = "1"
    if bin_dir is not None:
        env["BATRADE_BIN_DIR"] = str(bin_dir)
    env.update(extra_env or {})
    return subprocess.run(["bash", str(INSTALL), *args], cwd=str(cwd or REPO),
                          env=env, capture_output=True, text=True, timeout=180)


def _prefix_tree(tmp_path: Path) -> tuple[Path, Path]:
    prefix = tmp_path / "opt" / "batrade"
    (prefix / "batrade").mkdir(parents=True)
    (prefix / "batrade" / "__init__.py").write_text("__version__='x'\n", encoding="utf-8")
    (prefix / ".venv" / "bin").mkdir(parents=True)
    (prefix / "var" / "scans").mkdir(parents=True)
    (prefix / "var" / "batrade.db").write_text("db", encoding="utf-8")
    (prefix / "config.yaml").write_text("network: {}\n", encoding="utf-8")
    (prefix / ".env").write_text("TELEGRAM_TOKEN=\n", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "batrade").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    return prefix, bin_dir


# --------------------------------------------------------------------------- #
# Instalación de sistema
# --------------------------------------------------------------------------- #
def test_system_dry_run_plans_everything_and_writes_nothing(tmp_path):
    prefix = tmp_path / "opt" / "batrade"
    bin_dir = tmp_path / "bin"
    result = _run(["--system", "--dry-run", "--prefix", str(prefix)], bin_dir=bin_dir)
    assert result.returncode == 0, result.stderr
    salida = result.stdout + result.stderr
    assert "[dry-run]" in salida
    assert str(prefix) in salida
    assert str(bin_dir / "batrade") in salida
    assert "mkdir" in salida and "sync_tree.sh" in salida
    assert not prefix.exists()          # no se ha creado nada
    assert not bin_dir.exists()


def test_system_requires_root(monkeypatch, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("la suite corre como root: no se puede comprobar la negativa")
    result = _run(["--system", "--prefix", str(tmp_path / "opt")], fake_root=False)
    assert result.returncode == 1
    assert "sudo" in result.stderr.lower()


def test_system_help_mentions_new_modes():
    result = _run(["--help"], fake_root=False)
    assert result.returncode == 0
    assert "--system" in result.stdout and "--uninstall" in result.stdout
    assert "--dry-run" in result.stdout and "--prefix" in result.stdout


def test_unknown_option_is_rejected():
    result = _run(["--inventado"], fake_root=False)
    assert result.returncode == 2


# --------------------------------------------------------------------------- #
# Desinstalación
# --------------------------------------------------------------------------- #
def test_uninstall_dry_run_keeps_everything(tmp_path):
    prefix, bin_dir = _prefix_tree(tmp_path)
    result = _run(["--uninstall", "--dry-run", "--prefix", str(prefix)],
                  bin_dir=bin_dir)
    assert result.returncode == 0, result.stderr
    assert prefix.exists() and (prefix / "batrade").exists()
    assert (bin_dir / "batrade").exists()


def test_uninstall_removes_code_but_keeps_data(tmp_path):
    prefix, bin_dir = _prefix_tree(tmp_path)
    result = _run(["--uninstall", "--prefix", str(prefix)], bin_dir=bin_dir)
    assert result.returncode == 0, result.stderr
    assert not (prefix / "batrade").exists()
    assert not (prefix / ".venv").exists()
    assert not (bin_dir / "batrade").exists()
    # Datos y configuración del operador intactos.
    assert (prefix / "var" / "batrade.db").read_text(encoding="utf-8") == "db"
    assert (prefix / "config.yaml").exists()
    assert (prefix / ".env").exists()
    assert "conservado" in result.stdout


def test_uninstall_purge_without_yes_aborts(tmp_path):
    prefix, bin_dir = _prefix_tree(tmp_path)
    result = _run(["--uninstall", "--purge", "--prefix", str(prefix)],
                  bin_dir=bin_dir)
    assert result.returncode != 0
    assert prefix.exists() and (prefix / "var").exists()
    assert (bin_dir / "batrade").exists()


def test_uninstall_purge_with_yes_removes_all(tmp_path):
    prefix, bin_dir = _prefix_tree(tmp_path)
    result = _run(["--uninstall", "--purge", "--yes", "--prefix", str(prefix)],
                  bin_dir=bin_dir)
    assert result.returncode == 0, result.stderr
    assert not prefix.exists()
    assert not (bin_dir / "batrade").exists()


def test_uninstall_refuses_with_live_sensor(tmp_path):
    prefix, bin_dir = _prefix_tree(tmp_path)
    (prefix / "var" / "sensor.pid").write_text(str(os.getpid()), encoding="utf-8")
    result = _run(["--uninstall", "--prefix", str(prefix)], bin_dir=bin_dir)
    assert result.returncode != 0
    assert "proceso vivo" in result.stderr
    assert (prefix / "batrade").exists()


# --------------------------------------------------------------------------- #
# scripts/sync_tree.sh
# --------------------------------------------------------------------------- #
def _mini_tree(tmp_path: Path) -> tuple[Path, Path]:
    src = tmp_path / "src"
    (src / "batrade").mkdir(parents=True)
    (src / "batrade" / "mod.py").write_text("VERSION = 2\n", encoding="utf-8")
    (src / "config.yaml").write_text("repo: true\n", encoding="utf-8")
    (src / ".env.example").write_text("TOKEN=\n", encoding="utf-8")
    (src / ".git").mkdir()
    (src / ".git" / "HEAD").write_text("ref\n", encoding="utf-8")
    (src / "var").mkdir()
    (src / "var" / "batrade.db").write_text("datos del repo", encoding="utf-8")
    dst = tmp_path / "dst"
    dst.mkdir()
    (dst / "config.yaml").write_text("operador: true\n", encoding="utf-8")
    (dst / ".env").write_text("SECRETO=\n", encoding="utf-8")
    (dst / "var").mkdir()
    (dst / "var" / "batrade.db").write_text("datos del operador", encoding="utf-8")
    return src, dst


def test_sync_tree_copies_code_and_excludes_runtime(tmp_path):
    src, dst = _mini_tree(tmp_path)
    result = subprocess.run(["bash", str(SYNC), str(src), str(dst)],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert (dst / "batrade" / "mod.py").read_text(encoding="utf-8") == "VERSION = 2\n"
    assert (dst / ".env.example").exists()
    assert not (dst / ".git").exists()
    assert (dst / "var" / "batrade.db").read_text(encoding="utf-8") == "datos del operador"


def test_sync_tree_is_idempotent_and_preserves_operator_files(tmp_path):
    src, dst = _mini_tree(tmp_path)
    for _ in range(2):
        result = subprocess.run(["bash", str(SYNC), str(src), str(dst)],
                                capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr
    assert (dst / "config.yaml").read_text(encoding="utf-8") == "operador: true\n"
    assert (dst / ".env").read_text(encoding="utf-8") == "SECRETO=\n"
    assert (dst / "var" / "batrade.db").read_text(encoding="utf-8") == "datos del operador"
    assert "config.yaml existente conservado" in result.stdout


def test_sync_tree_first_install_copies_config(tmp_path):
    src, _dst = _mini_tree(tmp_path)
    dst = tmp_path / "nuevo"
    result = subprocess.run(["bash", str(SYNC), str(src), str(dst)],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert (dst / "config.yaml").read_text(encoding="utf-8") == "repo: true\n"


def test_sync_tree_dry_run_writes_nothing(tmp_path):
    src, _dst = _mini_tree(tmp_path)
    dst = tmp_path / "nuevo"
    result = subprocess.run(["bash", str(SYNC), str(src), str(dst), "--dry-run"],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "[dry-run]" in result.stdout
    assert not dst.exists()


def test_sync_tree_rejects_prefix_inside_repo(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    result = subprocess.run(["bash", str(SYNC), str(src), str(src / "dentro")],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 2
    assert "dentro del origen" in result.stderr


# --------------------------------------------------------------------------- #
# Resolución de la raíz
# --------------------------------------------------------------------------- #
def test_resolve_root_precedence(monkeypatch, tmp_path):
    monkeypatch.delenv("BATRADE_ROOT", raising=False)
    assert cli.resolve_root(SimpleNamespace(root=None)) == cli.package_root()

    monkeypatch.setenv("BATRADE_ROOT", str(tmp_path))
    assert cli.resolve_root(SimpleNamespace(root=None)) == tmp_path

    explicit = tmp_path / "explicito"
    assert cli.resolve_root(SimpleNamespace(root=str(explicit))) == explicit.resolve()


def _write_config(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "config.yaml").write_text(CONFIG_MIN, encoding="utf-8")


def _doctor(cwd: Path, env_extra: dict[str, str] | None = None) -> str:
    env = {k: v for k, v in os.environ.items() if k != "BATRADE_ROOT"}
    env.update(env_extra or {})
    result = subprocess.run([sys.executable, "-m", "batrade", "doctor"],
                            cwd=str(cwd), env=env, capture_output=True, text=True,
                            timeout=120)
    assert result.returncode == 0, result.stderr
    return result.stdout + result.stderr


def test_cli_uses_package_root_from_any_directory(tmp_path):
    """Sin --root ni BATRADE_ROOT, la raíz es el paquete, no el directorio actual."""
    salida = _doctor(tmp_path)
    assert str(cli.package_root()) in salida


def test_cli_honours_batrade_root(tmp_path):
    ajeno = tmp_path / "instalado"
    _write_config(ajeno)
    salida = _doctor(tmp_path, {"BATRADE_ROOT": str(ajeno)})
    assert str(ajeno) in salida
    assert (ajeno / "var" / "batrade.db").exists()


def test_cli_root_flag_wins_over_env(tmp_path):
    ajeno = tmp_path / "instalado"
    _write_config(ajeno)
    otro = tmp_path / "otro"
    _write_config(otro)
    env = {k: v for k, v in os.environ.items() if k != "BATRADE_ROOT"}
    env["BATRADE_ROOT"] = str(ajeno)
    result = subprocess.run([sys.executable, "-m", "batrade", "--root", str(otro),
                             "doctor"], cwd=str(tmp_path), env=env,
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    assert str(otro) in result.stdout
    assert (otro / "var" / "batrade.db").exists()


# --------------------------------------------------------------------------- #
# Shellcheck (si está disponible)
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(shutil.which("shellcheck") is None,
                    reason="shellcheck no está instalado")
@pytest.mark.parametrize("script", [INSTALL, SYNC])
def test_shellcheck_clean(script):
    result = subprocess.run(["shellcheck", "-x", str(script)],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout
