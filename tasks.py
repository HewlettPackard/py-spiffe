"""
(C) Copyright 2021 Hewlett Packard Enterprise Development LP

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

from __future__ import annotations

import argparse
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence


ROOT = Path(__file__).resolve().parent
SPIFFE_PROTO_DIR = ROOT / "spiffe" / "src" / "spiffe" / "_proto"
ROOT_LINT_TARGETS = ("tasks.py",)
COPYRIGHT_PREFIX = '"""\n(C) Copyright 2021 Hewlett Packard Enterprise Development LP\n'
COPYRIGHT_TEXT = """\"\"\"
(C) Copyright 2021 Hewlett Packard Enterprise Development LP

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
\"\"\"\n\n"""


@dataclass(frozen=True)
class PackageTasks:
    name: str
    directory: str
    verifytypes_module: str | None = None
    has_unit_tests: bool = True
    has_integration_tests: bool = True


PACKAGES = {
    "examples": PackageTasks(
        name="py-spiffe-examples",
        directory="examples",
        has_unit_tests=False,
        has_integration_tests=False,
    ),
    "spiffe": PackageTasks(
        name="spiffe",
        directory="spiffe",
        verifytypes_module="spiffe",
    ),
    "spiffe-tls": PackageTasks(
        name="spiffe-tls",
        directory="spiffe-tls",
        verifytypes_module="spiffetls",
    ),
}
PACKAGE_NAMES = tuple(PACKAGES)


def parse_package_name(name: str) -> str:
    # Use `type=` validation instead of `choices=` for `nargs="*"` package args.
    # The documented behavior for `type=` is stable:
    # https://docs.python.org/3/library/argparse.html#type
    # while `choices=` with `nargs="*"` rejects an empty argument list as
    # `invalid choice: []` on Python 3.10 and 3.11. This no longer reproduces on
    # Python 3.12+, so replace this with `choices=PACKAGE_NAMES` once the minimum
    # supported Python version is 3.12 or newer.
    if name not in PACKAGES:
        raise argparse.ArgumentTypeError(
            f"unknown package {name!r}; expected one of: {', '.join(PACKAGE_NAMES)}"
        )
    return name


def uv(*args: str, cwd: Optional[Path] = None) -> None:
    if cwd is None:
        cwd = ROOT
    subprocess.run(("uv", *args), cwd=cwd, check=True)


def uv_run(*args: str, cwd: Optional[Path] = None) -> None:
    uv("run", *args, cwd=cwd)


def uv_package(package: PackageTasks, cmd: str, *args: str) -> None:
    uv(
        cmd,
        "--project",
        str(ROOT),
        "--package",
        package.name,
        *args,
        # Without this mypy doesn't pick up the `files` config.
        cwd=ROOT / package.directory,
    )


def run_uv_package(package: PackageTasks, *args: str) -> None:
    uv_package(package, "run", *args)


def capture(cmd: Sequence[str], *, cwd: Path = ROOT) -> str:
    return subprocess.check_output(cmd, cwd=cwd, text=True)


def selected_packages(names: Sequence[str]) -> list[PackageTasks]:
    package_names = names or PACKAGE_NAMES
    return [PACKAGES[name] for name in package_names]


def format_command(args: argparse.Namespace) -> None:
    uv_run("ruff", "format", *ROOT_LINT_TARGETS)
    for package in selected_packages(args.packages):
        run_uv_package(package, "ruff", "format")


def lint(args: argparse.Namespace) -> None:
    uv_run("ruff", "format", "--check", "--diff", *ROOT_LINT_TARGETS)
    uv_run("ruff", "check", *ROOT_LINT_TARGETS)
    uv_run("mypy", *ROOT_LINT_TARGETS)
    uv_run("pyright", *ROOT_LINT_TARGETS)
    for package in selected_packages(args.packages):
        run_uv_package(
            package,
            "ruff",
            "format",
            "--check",
            "--diff",
        )
        run_uv_package(package, "ruff", "check")
        run_uv_package(package, "--all-groups", "mypy")
        run_uv_package(package, "--all-groups", "pyright")
        if package.verifytypes_module is not None:
            run_uv_package(
                package,
                "pyright",
                "--verifytypes",
                package.verifytypes_module,
                "--ignoreexternal",
            )


def build(args: argparse.Namespace) -> None:
    for package in selected_packages(args.packages):
        uv_package(package, "build")


def test(args: argparse.Namespace) -> None:
    for package in selected_packages(args.packages):
        if not package.has_unit_tests:
            print(f"{package.name}: no automated tests")
            continue
        run_uv_package(
            package,
            "--all-groups",
            "pytest",
            "tests/unit",
            "-W",
            "ignore::DeprecationWarning",
        )


def integration(args: argparse.Namespace) -> None:
    for package in selected_packages(args.packages):
        if not package.has_integration_tests:
            print(f"{package.name}: no integration tests")
            continue
        run_uv_package(
            package,
            "--all-groups",
            "pytest",
            "tests/integration",
            "-W",
            "ignore::DeprecationWarning",
        )


def compile_proto(_: argparse.Namespace) -> None:
    spiffe_dir = ROOT / "spiffe"
    run_uv_package(
        PACKAGES["spiffe"],
        "--all-groups",
        "python",
        "-m",
        "grpc_tools.protoc",
        f"-I{spiffe_dir / 'src'}",
        f"--python_out={spiffe_dir / 'src'}",
        f"--mypy_out={spiffe_dir / 'src'}",
        f"--grpc_python_out={spiffe_dir / 'src'}",
        f"{SPIFFE_PROTO_DIR / 'workload.proto'}",
    )


def test_coverage(_: argparse.Namespace) -> None:
    spiffe_dir = ROOT / "spiffe"
    uv_run("coverage", "run", "-m", "pytest", cwd=spiffe_dir)
    uv_run("coverage", "report", "-m", cwd=spiffe_dir)
    uv_run("coverage", "xml", cwd=spiffe_dir)
    uv_run("coverage", "html", cwd=spiffe_dir)


def tracked_python_files() -> list[Path]:
    paths = capture(("git", "ls-files", "*.py")).splitlines()
    result: list[Path] = []
    for relative_path in paths:
        path = Path(relative_path)
        if path.name == "__init__.py":
            continue
        if "_proto" in path.parts:
            continue
        absolute_path = ROOT / path
        if not absolute_path.exists():
            continue
        result.append(absolute_path)
    return result


def copyright_command(_: argparse.Namespace) -> None:
    for path in tracked_python_files():
        content = path.read_text()
        if content.startswith(COPYRIGHT_PREFIX):
            continue
        print(f"Adding copyright to: {path.relative_to(ROOT)}")
        path.write_text(COPYRIGHT_TEXT + content)


def pre_commit(args: argparse.Namespace) -> None:
    copyright_command(args)
    lint(args)


def all_command(args: argparse.Namespace) -> None:
    lint(args)
    build(args)
    test(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Repository task runner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_package_argument(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "packages",
            nargs="*",
            type=parse_package_name,
            help="Subset of packages to operate on",
        )

    format_parser = subparsers.add_parser("format", help="Format source files")
    add_package_argument(format_parser)
    format_parser.set_defaults(func=format_command)

    lint_parser = subparsers.add_parser("lint", help="Run lint and type checks")
    add_package_argument(lint_parser)
    lint_parser.set_defaults(func=lint)

    build_parser = subparsers.add_parser("build", help="Build packages")
    add_package_argument(build_parser)
    build_parser.set_defaults(func=build)

    test_parser = subparsers.add_parser("test", help="Run unit tests")
    add_package_argument(test_parser)
    test_parser.set_defaults(func=test)

    integration_parser = subparsers.add_parser("integration", help="Run integration tests")
    add_package_argument(integration_parser)
    integration_parser.set_defaults(func=integration)

    all_parser = subparsers.add_parser("all", help="Run lint, build, and unit tests")
    add_package_argument(all_parser)
    all_parser.set_defaults(func=all_command)

    compile_proto_parser = subparsers.add_parser(
        "compile-proto",
        help="Regenerate gRPC code for spiffe",
    )
    compile_proto_parser.set_defaults(func=compile_proto)

    coverage_parser = subparsers.add_parser(
        "test-coverage",
        help="Run spiffe tests with coverage reporting",
    )
    coverage_parser.set_defaults(func=test_coverage)

    copyright_parser = subparsers.add_parser(
        "copyright",
        help="Add copyright headers to Python files",
    )
    copyright_parser.set_defaults(func=copyright_command)

    pre_commit_parser = subparsers.add_parser(
        "pre-commit",
        help="Run copyright header updates and lint checks",
    )
    add_package_argument(pre_commit_parser)
    pre_commit_parser.set_defaults(func=pre_commit)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
