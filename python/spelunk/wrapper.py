from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from shutil import which
from typing import Any, Iterable, Mapping, Optional, Sequence, Union

PathLike = Union[str, os.PathLike[str]]


class SpelunkError(RuntimeError):
    """Raised when the spelunk CLI exits unsuccessfully."""

    def __init__(self, result: "SpelunkResult") -> None:
        message = result.stderr.strip() or result.stdout.strip()
        if not message:
            message = f"spelunk exited with status {result.returncode}"
        super().__init__(message)
        self.result = result


@dataclass(frozen=True)
class SpelunkResult:
    """Completed spelunk invocation."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def check(self) -> "SpelunkResult":
        if not self.ok:
            raise SpelunkError(self)
        return self

    def json(self) -> object:
        return json.loads(self.stdout)

    @property
    def lines(self) -> list[str]:
        return self.stdout.splitlines()


def find_spelunk(start: Optional[PathLike] = None) -> str:
    """Find a spelunk executable from SPELUNK_BIN, common build paths, or PATH."""

    env_bin = os.environ.get("SPELUNK_BIN")
    if env_bin:
        return env_bin

    root = Path(start or Path.cwd()).resolve()
    candidates = [
        root / "build" / "cli" / "spelunk",
        root / "build" / "cli" / "Release" / "spelunk",
        root / "build" / "cli" / "Debug" / "spelunk",
        root / "cmake-build-release" / "cli" / "spelunk",
        root / "cmake-build-debug" / "cli" / "spelunk",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    path_bin = which("spelunk")
    if path_bin:
        return path_bin

    raise FileNotFoundError(
        "could not find spelunk; set SPELUNK_BIN or build ./build/cli/spelunk"
    )


class Spelunk:
    """Small subprocess wrapper around the spelunk CLI."""

    def __init__(
        self,
        binary: Optional[PathLike] = None,
        *,
        spelunk_bin: Optional[PathLike] = None,
        cwd: Optional[PathLike] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> None:
        self.binary = str(binary) if binary is not None else None
        self.cwd = str(cwd) if cwd is not None else None
        self.spelunk_bin = str(spelunk_bin) if spelunk_bin is not None else find_spelunk(cwd)
        self.env = dict(env) if env is not None else None

    def with_binary(self, binary: PathLike) -> "Spelunk":
        return Spelunk(binary, spelunk_bin=self.spelunk_bin, cwd=self.cwd, env=self.env)

    def function(self, address: Union[int, str]) -> "SpelunkFunction":
        return SpelunkFunction(self, address)

    def run(
        self,
        *args: object,
        binary: Optional[PathLike] = None,
        check: bool = True,
        input: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> SpelunkResult:
        cmd = [self.spelunk_bin, *self._flatten(args)]
        selected_binary = str(binary) if binary is not None else self.binary
        if selected_binary is not None:
            cmd.append(selected_binary)

        completed = subprocess.run(
            cmd,
            cwd=self.cwd,
            env=self._merged_env(),
            input=input,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        result = SpelunkResult(
            args=tuple(cmd),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        return result.check() if check else result

    def pseudo(self, symbol: str = "main", **options: object) -> str:
        return self.run("-p", "-s", symbol, *self._options(options)).stdout

    def disasm(self, symbol: str = "main", **options: object) -> str:
        return self.run("-d", "-s", symbol, *self._options(options)).stdout

    def cfg(self, symbol: str = "main", **options: object) -> str:
        return self.run("-c", "-s", symbol, *self._options(options)).stdout

    def ir(self, symbol: str = "main", **options: object) -> str:
        return self.run("-i", "-s", symbol, *self._options(options)).stdout

    def ssa(self, symbol: str = "main", **options: object) -> str:
        return self.run("--ssa", "-s", symbol, *self._options(options)).stdout

    def disasm_at(
        self,
        address: Union[int, str],
        count: Optional[int] = None,
        **options: object,
    ) -> str:
        args: list[object] = ["--disasm-at", self._addr(address)]
        if count is not None:
            args.extend(["--count", count])
        return self.run(*args, *self._options(options)).stdout

    def callees(
        self,
        address: Union[int, str],
        *,
        json: bool = False,
        **options: object,
    ) -> object:
        return self._run_jsonable("--callees", self._addr(address), json=json, **options)

    def containing_function(
        self,
        address: Union[int, str],
        *,
        json: bool = True,
        **options: object,
    ) -> object:
        return self._run_jsonable(
            "--containing-fn",
            self._addr(address),
            json=json,
            **options,
        )

    def refs_to(
        self,
        address: Union[int, str],
        *,
        loose: bool = False,
        json: bool = False,
        **options: object,
    ) -> object:
        flag = "--refs-to-loose" if loose else "--refs-to"
        return self._run_jsonable(flag, self._addr(address), json=json, **options)

    def state_map(
        self,
        address: Union[int, str],
        *,
        json: bool = False,
        **options: object,
    ) -> object:
        return self._run_jsonable("--state-map", self._addr(address), json=json, **options)

    def state_lifetime(
        self,
        address: Union[int, str],
        *,
        json: bool = True,
        **options: object,
    ) -> object:
        return self._run_jsonable(
            "--state-lifetime",
            self._addr(address),
            json=json,
            **options,
        )

    def branch_on(
        self,
        address: Union[int, str],
        *,
        json: bool = True,
        **options: object,
    ) -> object:
        return self._run_jsonable("--branch-on", self._addr(address), json=json, **options)

    def side_effects(
        self,
        function: Union[int, str],
        *,
        json: bool = True,
        **options: object,
    ) -> object:
        return self._run_jsonable(
            "--side-effects",
            self._addr(function),
            json=json,
            **options,
        )

    def object_roles(
        self,
        function: Union[int, str],
        *,
        json: bool = True,
        **options: object,
    ) -> object:
        return self._run_jsonable(
            "--object-roles",
            self._addr(function),
            json=json,
            **options,
        )

    def guard_map(
        self,
        address: Union[int, str],
        *,
        json: bool = False,
        **options: object,
    ) -> object:
        result = self.run(
            "--guard-map",
            self._addr(address),
            *(["--json"] if json else []),
            *self._options(options),
        )
        return result.json() if json else result.stdout

    def explain_vcall(
        self,
        obj: Union[int, str],
        offset: Union[int, str],
        *,
        json: bool = True,
        **options: object,
    ) -> object:
        spec = f"{self._addr(obj)}:{self._addr(offset)}"
        return self._run_jsonable("--explain-vcall", spec, json=json, **options)

    def dump_object(
        self,
        address: Union[int, str],
        size: Union[int, str],
        *,
        json: bool = True,
        **options: object,
    ) -> object:
        return self._run_jsonable(
            "--dump-object",
            self._addr(address),
            "--size",
            self._addr(size),
            json=json,
            **options,
        )

    def explain_address(
        self,
        address: Union[int, str],
        *,
        json: bool = True,
        **options: object,
    ) -> object:
        result = self.run(
            "--explain-address",
            self._addr(address),
            *(["--json"] if json else []),
            *self._options(options),
        )
        return result.json() if json else result.stdout

    def explain_path(
        self,
        addresses: Sequence[Union[int, str]],
        *,
        include_guard_map: bool = False,
        include_containing: bool = True,
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        previous: Optional[dict[str, Any]] = None
        for index, address in enumerate(addresses):
            row = self.explain_address(address, json=True)
            if not isinstance(row, dict):
                raise TypeError("spelunk --explain-address returned non-object JSON")
            row["index"] = index
            if previous is not None:
                row["previous"] = previous.get("address")
            if include_containing and row.get("containing_function"):
                row["function"] = row["containing_function"]
            if include_guard_map and row.get("kind") in {"function", "code"}:
                row["guard_map"] = self.guard_map(address, json=True)
            rows.append(row)
            previous = row
        return rows

    def investigate(
        self,
        address: Union[int, str],
        *,
        disasm_count: int = 80,
        include_pseudo: bool = True,
    ) -> dict[str, Any]:
        fn = self.function(address)
        report: dict[str, Any] = {
            "address": self._addr(address),
            "explain": fn.explain(json=True),
            "containing_function": self.containing_function(address, json=True),
            "disasm": fn.disasm(count=disasm_count),
            "callees": fn.callees(json=True),
            "guard_map": fn.guard_map(json=True),
            "side_effects": fn.side_effects(json=True),
            "object_roles": fn.object_roles(json=True),
        }
        if include_pseudo:
            report["pseudo"] = fn.pseudo()
        return report

    def annotate_batch(
        self,
        path: PathLike,
        findings: Iterable[Union[str, Mapping[str, object]]],
        *,
        apply: bool = True,
        dry_run: bool = False,
        annotations: Optional[PathLike] = None,
    ) -> SpelunkResult:
        script_path = Path(path)
        script_path.parent.mkdir(parents=True, exist_ok=True)
        script_path.write_text(self._findings_to_script(findings), encoding="utf-8")
        if not apply:
            return SpelunkResult(args=(), returncode=0, stdout="", stderr="")

        args: list[object] = ["--apply", script_path]
        if dry_run:
            args.append("--dry-run")
        if annotations is not None:
            args.extend(["--annotations", annotations])
        return self.run(*args, check=True)

    def functions(self, pattern: Optional[str] = None, **options: object) -> str:
        args: list[object] = ["--functions"]
        if pattern:
            args[0] = f"--functions={pattern}"
        return self.run(*args, *self._options(options)).stdout

    def functions_json(self, pattern: Optional[str] = None, **options: object) -> object:
        args: list[object] = [f"--functions={pattern}"] if pattern else ["--functions"]
        return self.run(
            *args,
            "--json",
            *self._options(options),
        ).json()

    def strings(self, **options: object) -> str:
        return self.run("--strings", *self._options(options)).stdout

    def xrefs(self, **options: object) -> str:
        return self.run("--xrefs", *self._options(options)).stdout

    def validate(self, name: str, *, json: bool = True, check: bool = False) -> object:
        result = self.run(
            "--validate",
            name,
            *(["--json"] if json else []),
            check=check,
        )
        return result.json() if json else result.stdout

    def _merged_env(self) -> Optional[dict[str, str]]:
        if self.env is None:
            return None
        merged = os.environ.copy()
        merged.update(self.env)
        return merged

    def _run_jsonable(
        self,
        *args: object,
        json: bool = False,
        **options: object,
    ) -> object:
        result = self.run(
            *args,
            *(["--json"] if json else []),
            *self._options(options),
        )
        return result.json() if json else result.stdout

    @classmethod
    def _flatten(cls, args: Iterable[object]) -> list[str]:
        out: list[str] = []
        for arg in args:
            if arg is None or arg is False:
                continue
            if isinstance(arg, (list, tuple)):
                out.extend(cls._flatten(arg))
                continue
            out.append(str(arg))
        return out

    @staticmethod
    def _options(options: Mapping[str, object]) -> list[object]:
        args: list[object] = []
        for name, value in options.items():
            flag = "--" + name.replace("_", "-")
            if value is None or value is False:
                continue
            if value is True:
                args.append(flag)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    args.extend([flag, item])
            else:
                args.extend([flag, value])
        return args

    @staticmethod
    def _addr(address: Union[int, str]) -> str:
        if isinstance(address, int):
            return hex(address)
        return str(address)

    @classmethod
    def _findings_to_script(
        cls,
        findings: Iterable[Union[str, Mapping[str, object]]],
    ) -> str:
        sections: dict[str, list[str]] = {
            "rename": [],
            "note": [],
            "signature": [],
            "constant": [],
        }
        raw: list[str] = []
        for finding in findings:
            if isinstance(finding, str):
                raw.append(finding.rstrip())
                continue

            addr = finding.get("address", finding.get("addr", finding.get("va")))
            if addr is None and "constant" not in finding:
                raise ValueError(f"finding has no address: {finding!r}")
            lhs = cls._addr(addr) if addr is not None else cls._addr(finding["constant"])
            meta = cls._meta_suffix(finding)

            if finding.get("name"):
                sections["rename"].append(f"{lhs} = {finding['name']}{meta}")
            if finding.get("note"):
                sections["note"].append(
                    f"{lhs} = {cls._quote_spelunk(finding['note'])}{meta}"
                )
            if finding.get("signature"):
                sections["signature"].append(f"{lhs} = {finding['signature']}{meta}")
            if finding.get("constant") is not None and finding.get("constant_name"):
                sections["constant"].append(f"{lhs} = {finding['constant_name']}")

        blocks: list[str] = []
        for section, lines in sections.items():
            if lines:
                blocks.append(f"[{section}]\n" + "\n".join(lines))
        if raw:
            blocks.append("\n".join(raw))
        return "\n\n".join(blocks) + ("\n" if blocks else "")

    @staticmethod
    def _meta_suffix(finding: Mapping[str, object]) -> str:
        parts: list[str] = []
        if finding.get("confidence") is not None:
            parts.append(f"conf={finding['confidence']}")
        if finding.get("source") is not None:
            parts.append(f"src={finding['source']}")
        if finding.get("evidence") is not None:
            evidence = str(finding["evidence"]).replace(";", ",")
            parts.append(f"ev={evidence}")
        return " ; " + " ; ".join(parts) if parts else ""

    @staticmethod
    def _quote_spelunk(value: object) -> str:
        text = str(value)
        if not any(ch in text for ch in (" ", "\t", "=", "#", "%", '"', "\\")):
            return text
        escaped = (
            text.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        )
        return f'"{escaped}"'


@dataclass(frozen=True)
class SpelunkFunction:
    spelunk: Spelunk
    address: Union[int, str]

    @property
    def va(self) -> str:
        return self.spelunk._addr(self.address)

    def pseudo(self, **options: object) -> str:
        return self.spelunk.pseudo(self.va, **options)

    def disasm(self, count: Optional[int] = None, **options: object) -> str:
        return self.spelunk.disasm_at(self.address, count=count, **options)

    def callees(self, *, json: bool = False, **options: object) -> object:
        return self.spelunk.callees(self.address, json=json, **options)

    def guard_map(self, *, json: bool = False, **options: object) -> object:
        return self.spelunk.guard_map(self.address, json=json, **options)

    def explain(self, *, json: bool = True, **options: object) -> object:
        return self.spelunk.explain_address(self.address, json=json, **options)

    def containing_function(self, *, json: bool = True, **options: object) -> object:
        return self.spelunk.containing_function(self.address, json=json, **options)

    def refs_to(self, *, loose: bool = False, json: bool = False, **options: object) -> object:
        return self.spelunk.refs_to(self.address, loose=loose, json=json, **options)

    def state_lifetime(self, *, json: bool = True, **options: object) -> object:
        return self.spelunk.state_lifetime(self.address, json=json, **options)

    def branch_on(self, *, json: bool = True, **options: object) -> object:
        return self.spelunk.branch_on(self.address, json=json, **options)

    def side_effects(self, *, json: bool = True, **options: object) -> object:
        return self.spelunk.side_effects(self.address, json=json, **options)

    def object_roles(self, *, json: bool = True, **options: object) -> object:
        return self.spelunk.object_roles(self.address, json=json, **options)

    def investigate(self, *, disasm_count: int = 80, include_pseudo: bool = True) -> dict[str, Any]:
        return self.spelunk.investigate(
            self.address,
            disasm_count=disasm_count,
            include_pseudo=include_pseudo,
        )
