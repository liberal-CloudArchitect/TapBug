"""Offline AST and manifest validation for generated low-risk wheels."""

from __future__ import annotations

import ast
import sys
from collections.abc import Iterable
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from .models import ValidationReport, WheelManifest

NETWORK_IMPORTS = frozenset(
    {"socket", "http", "httpx", "requests", "urllib", "aiohttp", "ftplib", "telnetlib"}
)
COMMAND_IMPORTS = frozenset({"subprocess", "pty", "shlex"})
FILESYSTEM_IMPORTS = frozenset({"os", "shutil", "tempfile"})
FORBIDDEN_IMPORTS = (
    NETWORK_IMPORTS
    | COMMAND_IMPORTS
    | FILESYSTEM_IMPORTS
    | frozenset({"importlib", "ctypes", "marshal", "pickle", "shelve", "runpy", "code", "builtins"})
)
DYNAMIC_CALLS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "getattr",
        "setattr",
        "delattr",
        "globals",
        "locals",
        "vars",
    }
)
WRITE_METHODS = frozenset(
    {
        "write_text",
        "write_bytes",
        "touch",
        "mkdir",
        "unlink",
        "rmdir",
        "rename",
        "replace",
        "chmod",
        "chown",
    }
)

_HASH_EXCLUDED_FILENAMES = frozenset({"wheel-manifest.json"})


def artifact_sha256_for_directory(root: Path) -> str:
    """Hash filenames and bytes deterministically, excluding interpreter cache files."""
    root = root.resolve()
    digest = sha256()
    for path in sorted(
        item
        for item in root.rglob("*")
        if item.is_file()
        and not item.is_symlink()
        and path_name_not_excluded(item)
        and "__pycache__" not in item.parts
    ):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        content = path.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"sha256:{digest.hexdigest()}"


def path_name_not_excluded(path: Path) -> bool:
    return path.name not in _HASH_EXCLUDED_FILENAMES


class _SafetyVisitor(ast.NodeVisitor):
    def __init__(self, *, declared_dependencies: Iterable[str], local_modules: set[str]) -> None:
        self.declared_dependencies = {
            item.split("[", 1)[0].replace("-", "_") for item in declared_dependencies
        }
        self.local_modules = local_modules
        self.imports: set[str] = set()
        self.violations: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._check_import(alias.name, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level == 0 and node.module:
            self._check_import(node.module, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        if name in DYNAMIC_CALLS or name in {"importlib.import_module", "importlib.reload"}:
            self.violations.append(
                f"line {node.lineno}: reflection or dynamic execution/import call {name}"
            )
        if name == "open":
            mode = _open_mode(node)
            if any(flag in mode for flag in "wax+"):
                self.violations.append(f"line {node.lineno}: filesystem write via open")
        if name.rsplit(".", 1)[-1] in WRITE_METHODS:
            self.violations.append(f"line {node.lineno}: filesystem mutation via {name}")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in {"__builtins__", "__loader__", "__spec__", "__code__", "__globals__"}:
            self.violations.append(f"line {node.lineno}: reflective attribute access {node.attr}")
        self.generic_visit(node)

    def _check_import(self, name: str, line: int) -> None:
        root = name.split(".", 1)[0]
        self.imports.add(root)
        if root in FORBIDDEN_IMPORTS:
            self.violations.append(f"line {line}: forbidden import {root}")
        elif (
            root not in self.local_modules
            and root not in self.declared_dependencies
            and root not in _stdlib_modules()
        ):
            self.violations.append(f"line {line}: undeclared dependency {root}")


def _stdlib_modules() -> frozenset[str]:
    return frozenset(getattr(sys, "stdlib_module_names", ())) | frozenset({"__future__"})


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _open_mode(node: ast.Call) -> str:
    if (
        len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
    ):
        return node.args[1].value
    for keyword in node.keywords:
        if (
            keyword.arg == "mode"
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
        ):
            return keyword.value.value
    return "r"


class WheelValidator:
    """Validate a generated wheel without importing or executing its code."""

    def validate(self, manifest: WheelManifest, artifact_root: Path) -> ValidationReport:
        root = artifact_root.resolve()
        violations: list[str] = []
        if not root.is_dir():
            violations.append("artifact root does not exist or is not a directory")
            return self._report(manifest, None, violations, (), (), ())
        for candidate in root.rglob("*"):
            if candidate.is_symlink():
                violations.append(
                    f"artifact contains forbidden symlink: {candidate.relative_to(root).as_posix()}"
                )
        artifact_hash = artifact_sha256_for_directory(root)
        if manifest.artifact_sha256 is None:
            violations.append("manifest has no artifact_sha256")
        elif manifest.artifact_sha256 != artifact_hash:
            violations.append("artifact_sha256 does not match artifact contents")
        python_files = tuple(sorted(root.rglob("*.py")))
        if not python_files:
            violations.append("artifact contains no Python sources")
        test_paths: list[Path] = []
        for item in manifest.tests:
            candidate = (root / item).resolve()
            try:
                candidate.relative_to(root)
            except ValueError:
                violations.append(f"manifest test path escapes artifact root: {item}")
                continue
            test_paths.append(candidate)
        if any(not item.is_file() for item in test_paths) or len(test_paths) != len(manifest.tests):
            violations.append("manifest test path is absent from artifact")
        local_modules = {path.stem for path in python_files} | {
            path.parent.name for path in python_files
        }
        visitor = _SafetyVisitor(
            declared_dependencies=manifest.dependencies, local_modules=local_modules
        )
        checked: list[str] = []
        for path in python_files:
            relative = path.relative_to(root).as_posix()
            checked.append(relative)
            try:
                visitor.visit(ast.parse(path.read_text(encoding="utf-8"), filename=relative))
            except (OSError, UnicodeError, SyntaxError) as exc:
                violations.append(f"{relative}: unreadable or invalid Python: {exc}")
        violations.extend(visitor.violations)
        self._validate_generated_metadata(root, manifest, violations)
        return self._report(
            manifest,
            artifact_hash,
            violations,
            tuple(checked),
            tuple(sorted(visitor.imports)),
            tuple(sorted(manifest.dependencies)),
        )

    @staticmethod
    def _validate_generated_metadata(
        root: Path, manifest: WheelManifest, violations: list[str]
    ) -> None:
        """Validate generated artifacts when they claim to be Hermes template output.

        Hand-authored legacy fixtures intentionally need only the base manifest checks.
        """
        manifest_path = root / "wheel-manifest.json"
        if not manifest_path.exists():
            return
        required = ("capability-spec.json", "SBOM.spdx.json", "requirements.lock", "rules.json")
        for name in required:
            if not (root / name).is_file():
                violations.append(f"generated artifact metadata is missing: {name}")
        try:
            generated_manifest = WheelManifest.model_validate_json(
                manifest_path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            violations.append("generated wheel manifest is unreadable or invalid")
            return
        if generated_manifest != manifest:
            violations.append("generated wheel manifest does not match supplied manifest")
        try:
            spec = (root / "capability-spec.json").read_text(encoding="utf-8")
            sbom = (root / "SBOM.spdx.json").read_text(encoding="utf-8")
            if f'"id":"{manifest.id}"' not in spec.replace(" ", ""):
                violations.append("capability spec does not bind the manifest id")
            if '"spdxVersion"' not in sbom:
                violations.append("SBOM is not an SPDX document")
        except OSError:
            violations.append("generated artifact metadata is unreadable")

    @staticmethod
    def _report(
        manifest: WheelManifest,
        artifact_hash: str | None,
        violations: Iterable[str],
        checked: tuple[str, ...],
        imports: tuple[str, ...],
        sbom: tuple[str, ...],
    ) -> ValidationReport:
        materialized = tuple(violations)
        return ValidationReport(
            wheel_id=manifest.id,
            wheel_version=manifest.version,
            artifact_sha256=artifact_hash,
            passed=not materialized,
            violations=materialized,
            checked_files=checked,
            imports=imports,
            sbom=sbom,
            validated_at=datetime.now(UTC),
        )
