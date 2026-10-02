import ast
import json
import re
import shutil
import subprocess
import sys

from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKER = ROOT / "tools" / "layout_migration.json"

FILE_MOVES = {
    "web_app.py": "app/web.py",
    "assessment_engine.py": "app/engine/assessment.py",
    "scanner.py": "app/engine/crawler.py",
    "input_inventory.py": "app/engine/input_inventory.py",
    "request_planner.py": "app/engine/request_planner.py",
    "check_browser_xss.py": "app/checks/browser_xss.py",
    "check_sqli.py": "app/checks/boolean_sqli.py",
    "lab_app.py": "lab/app.py",
    "check_reflection.py": "tests/test_reflection.py",
    "validate_scanner.py": "tests/test_headers.py",
    "validate_request_planner.py": "tests/test_request_planner.py",
    "scan_lab.py": "legacy/zap/scan_lab.py",
    "scan_ui.py": "legacy/desktop/scan_ui.py",
    "scan_dashboard.py": "legacy/desktop/scan_dashboard.py",
    "read_report.py": "legacy/tools/read_report.py",
    "app.py": "legacy/prototypes/app.py",
    "main.py": "legacy/prototypes/main.py",
}

MODULE_MOVES = {
    "web_app": "app.web",
    "assessment_engine": "app.engine.assessment",
    "scanner": "app.engine.crawler",
    "input_inventory": "app.engine.input_inventory",
    "request_planner": "app.engine.request_planner",
    "check_browser_xss": "app.checks.browser_xss",
    "check_sqli": "app.checks.boolean_sqli",
    "lab_app": "lab.app",
    "check_reflection": "tests.test_reflection",
    "validate_scanner": "tests.test_headers",
    "validate_request_planner": "tests.test_request_planner",
}

PACKAGES = [
    "app",
    "app/engine",
    "app/checks",
    "lab",
    "tests",
]

RUN_CODE = '''from app.web import app


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False,
    )
'''

LEGACY_NOTE = """# Archived project files

These files are preserved from earlier project stages.
They are not used by the current web application.

Their original imports and paths are preserved for reference.
They may require adjustments before standalone execution.

Current application:
    python run.py

Current local lab:
    python -m lab.app
"""

SMOKE_CODE = """
from pathlib import Path
from app.web import app
from app.engine import crawler

expected_reports = Path.cwd() / "Report"
actual_reports = Path(crawler.__file__).resolve().parents[2] / "Report"
assert actual_reports == expected_reports, "Incorrect report directory."

with app.test_client() as client:
    for path in ("/", "/static/app.css", "/static/app.js"):
        response = client.get(
            path,
            base_url="http://127.0.0.1:5000",
        )
        assert response.status_code == 200, (
            f"{path} returned HTTP {response.status_code}"
        )

print("[PASS] Web application imports successfully.")
print("[PASS] Homepage, CSS, and JavaScript are available.")
print("[PASS] Reports still use the project Report directory.")
"""


def rewrite_imports(source):
    """Rewrite static imports without changing strings or comments."""
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    changes = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level != 0 or node.module not in MODULE_MOVES:
                continue

            line_index = node.lineno - 1
            old_line = lines[line_index]
            pattern = r"\bfrom\s+" + re.escape(node.module) + r"\s+import\b"
            replacement = f"from {MODULE_MOVES[node.module]} import"

            new_line, count = re.subn(
                pattern,
                replacement,
                old_line,
                count=1,
            )

            if count != 1:
                raise ValueError(
                    f"Could not rewrite import at line {node.lineno}."
                )

            changes.append((line_index, line_index + 1, new_line))

        elif isinstance(node, ast.Import):
            if not any(alias.name in MODULE_MOVES for alias in node.names):
                continue

            if node.lineno != node.end_lineno:
                raise ValueError(
                    "A multiline import needs manual review before migration."
                )

            line_index = node.lineno - 1
            old_line = lines[line_index]
            stripped = old_line.lstrip()

            if not stripped.startswith("import ") or ";" in old_line:
                raise ValueError(
                    "An inline import needs manual review before migration."
                )

            indentation = old_line[:len(old_line) - len(stripped)]
            imports = []

            for alias in node.names:
                module = MODULE_MOVES.get(alias.name, alias.name)
                name = alias.asname

                if alias.name in MODULE_MOVES and name is None:
                    name = alias.name

                imports.append(
                    f"{module} as {name}" if name else module
                )

            replacement = indentation + "import " + ", ".join(imports) + "\n"
            changes.append((line_index, line_index + 1, replacement))

    for start, end, replacement in sorted(changes, reverse=True):
        lines[start:end] = [replacement]

    result = "".join(lines)
    ast.parse(result)
    return result


def prepare_files():
    moves = dict(FILE_MOVES)

    for folder in ("templates", "static"):
        directory = ROOT / folder

        if not directory.is_dir():
            raise ValueError(f"Required folder is missing: {folder}")

        for path in directory.rglob("*"):
            if path.is_file():
                relative = path.relative_to(ROOT).as_posix()
                moves[relative] = f"app/{relative}"

    for old in moves:
        if not (ROOT / old).is_file():
            raise ValueError(f"Required file is missing: {old}")

    for folder in ("app", "lab", "tests", "legacy"):
        if (ROOT / folder).exists():
            raise ValueError(
                f"Destination already exists: {folder}. "
                "No files were changed."
            )

    if (ROOT / "run.py").exists():
        raise ValueError("run.py already exists. No files were changed.")

    prepared = {}

    for old, new in moves.items():
        source_path = ROOT / old

        if new.endswith(".py") and not new.startswith("legacy/"):
            source = source_path.read_text(encoding="utf-8-sig")
            source = rewrite_imports(source)

            if old == "scanner.py":
                original = 'Path(__file__).resolve().parent / "Report"'
                replacement = (
                    'Path(__file__).resolve().parents[2] / "Report"'
                )

                if source.count(original) != 1:
                    raise ValueError(
                        "The scanner report path differs from the expected "
                        "version. No files were changed."
                    )

                source = source.replace(original, replacement)

            ast.parse(source, filename=new)
            prepared[new] = source.encode("utf-8")
        else:
            prepared[new] = source_path.read_bytes()

    for package in PACKAGES:
        prepared[f"{package}/__init__.py"] = b""

    prepared["run.py"] = RUN_CODE.encode("utf-8")
    prepared["legacy/README.md"] = LEGACY_NOTE.encode("utf-8")

    return moves, prepared


def run_check(arguments):
    result = subprocess.run(
        [sys.executable, "-B", *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=60,
    )

    if result.stdout:
        print(result.stdout.strip())

    if result.returncode != 0:
        if result.stderr:
            print(result.stderr.strip())

        raise RuntimeError("A migration verification check failed.")


def main():
    if MARKER.exists():
        print("This layout migration has already completed.")
        print("No files were changed.")
        return 0

    moves, prepared = prepare_files()

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup = ROOT / "backups" / f"before-layout-{stamp}"
    backup.mkdir(parents=True, exist_ok=False)

    # Finish the backup before changing any original project file.
    for old in moves:
        destination = backup / old
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / old, destination)

    (backup / "manifest.json").write_text(
        json.dumps(moves, indent=2),
        encoding="utf-8",
    )

    written = []
    removed = []

    try:
        for relative, content in prepared.items():
            destination = ROOT / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            written.append(destination)
            destination.write_bytes(content)

        # All source files now have backed-up and relocated copies.
        for old in moves:
            source = ROOT / old
            source.unlink()
            removed.append(old)

        run_check(["-m", "tests.test_request_planner"])
        run_check(["-c", SMOKE_CODE])

        MARKER.write_text(
            json.dumps(
                {
                    "completed_at": datetime.now().isoformat(),
                    "backup": str(backup),
                    "moves": moves,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    except Exception:
        for old in removed:
            original = ROOT / old
            original.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup / old, original)

        for path in reversed(written):
            if path.is_file():
                path.unlink()

        for folder in ("app", "lab", "tests", "legacy"):
            directory = ROOT / folder
            if directory.is_dir():
                shutil.rmtree(directory)

        if MARKER.exists():
            MARKER.unlink()

        print("Migration failed. The original files were restored.")
        print(f"Backup: {backup}")
        raise

    # Remove empty source asset folders after successful verification.
    for folder in ("templates", "static"):
        directory = ROOT / folder

        subdirectories = sorted(
            (path for path in directory.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        )

        for path in subdirectories:
            if not any(path.iterdir()):
                path.rmdir()

        if directory.exists() and not any(directory.iterdir()):
            directory.rmdir()

    print("\nMigration completed successfully.")
    print(f"Backup: {backup}")
    print("Web application: python run.py")
    print("Local lab: python -m lab.app")
    print("Planner validation: python -m tests.test_request_planner")
    print("The Report directory and virtual environment were not moved.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"[ERROR] {error}")
        raise SystemExit(1)