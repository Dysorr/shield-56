"""Create a clean, Git-free source ZIP for a new public repository history."""
from pathlib import Path
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "generated-artifacts" / "publication"
EXPORT = DESTINATION / "shield-56"
ARCHIVE = DESTINATION / "shield-56-source.zip"


def included_files():
    files = set()
    root_files = (
        "README.md", "PROJECT_SPEC.md", "app.py", "pyproject.toml", "uv.lock",
        "requirements.txt", ".python-version", ".gitignore", ".gitattributes",
        ".streamlit/config.toml", "LICENSE",
    )
    for name in root_files:
        if (ROOT / name).is_file():
            files.add(name)
    for directory, suffixes in {
        ".github/workflows": {".yml", ".yaml"},
        "incident_analyzer": {".py"},
        "tests": {".py"},
        "evaluation": {".json"},
        "data/synthetic": {".csv", ".jsonl", ".xml", ".json", ".md"},
        "docs": {".md", ".html", ".png", ".jpg", ".jpeg"},
    }.items():
        base = ROOT / directory
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in suffixes:
                files.add(path.relative_to(ROOT).as_posix())
    for path in (ROOT / "scripts").glob("*"):
        if path.is_file() and path.suffix.lower() in {".py", ".ps1", ".sh"}:
            files.add(path.relative_to(ROOT).as_posix())
    # No uploaded evidence, local reports, Replit scaffolding/configuration,
    # memory, caches, Git objects, node_modules, or generated benchmarks.
    return sorted(files)


def create():
    if EXPORT.exists() or ARCHIVE.exists():
        raise FileExistsError(
            f"Refusing to replace an existing publication export: {DESTINATION}"
        )
    EXPORT.mkdir(parents=True)
    entries = included_files()
    for relative in entries:
        source = ROOT / relative
        if not source.resolve().is_relative_to(ROOT.resolve()):
            raise ValueError(f"Refusing to include a path outside the workspace: {relative}")
        target = EXPORT / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    with zipfile.ZipFile(ARCHIVE, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative in entries:
            archive.write(EXPORT / relative, f"shield-56/{relative}")
    return entries


if __name__ == "__main__":
    files = create()
    print(f"Created clean source export: {ARCHIVE.relative_to(ROOT)} ({len(files)} files).")
    print("No .git history, private logs, uploads, credentials, local caches, "
          "or generated benchmark output included.")
