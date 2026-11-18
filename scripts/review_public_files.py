"""Read-only publication triage. Print paths/categories, never matched values."""
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    "private_key": rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "aws_access_key": rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "github_token": rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b",
    "provider_token": rb"\b(?:sk_live_|sk-proj-|xox[baprs]-)[A-Za-z0-9_-]{12,}",
    "credential_assignment": rb"""(?i)(?:api[_-]?key|password|client[_-]?secret|access[_-]?token)\s*[:=]\s*["'][^"'\r\n]{8,}["']""",
    "url_credentials": rb"""[a-z]+://[^/\s:@]+:[^/\s@]+@""",
    "development_workspace_url": rb"https?://[A-Za-z0-9-]+\.replit\.dev\b",
}


def main():
    has_git = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"], cwd=ROOT,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0
    if has_git:
        names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
        names = [name for name in names if name]
    else:
        ignored = {".git", ".venv", "__pycache__", ".pytest_cache", "node_modules",
                   ".local", ".agents", "generated-artifacts"}
        names = [path.relative_to(ROOT).as_posix()
                 for path in ROOT.rglob("*")
                 if path.is_file() and not ignored.intersection(path.parts)]
    flags = []
    evidence = []
    workspace_links = []
    for name in names:
        path = ROOT / name
        if not path.is_file():
            continue
        content = path.read_bytes()
        for kind, expression in PATTERNS.items():
            if re.search(expression, content):
                flags.append({"path": name, "category": kind})
        if path.suffix.lower() in {".evtx", ".log", ".csv", ".jsonl", ".xml", ".pcap", ".pcapng"}:
            evidence.append({"path": name, "synthetic_directory": name.startswith("data/synthetic/")})
        if re.search(PATTERNS["development_workspace_url"], content):
            workspace_links.append(name)
    # Scan every unique blob reachable through any local ref. Only report
    # categories and paths; never print matching bytes or author addresses.
    history = {
        "available": has_git, "unique_reachable_objects_scanned": 0,
        "credential_pattern_flags": [], "event_log_or_packet_capture_path_count": 0,
        "distinct_author_or_committer_email_count": 0,
    }
    if has_git:
        # Scan every unique blob reachable through any local ref. Only report
        # categories and paths; never print matching bytes or author addresses.
        listing = subprocess.check_output(
            ["git", "rev-list", "--objects", "--all"], cwd=ROOT
        ).decode(errors="replace").splitlines()
        objects = {}
        for line in listing:
            object_id, separator, path = line.partition(" ")
            if separator:
                objects.setdefault(object_id, path)
        process = subprocess.Popen(
            ["git", "cat-file", "--batch"], cwd=ROOT,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        output, _ = process.communicate(("\n".join(objects) + "\n").encode("ascii"))
        if process.returncode:
            raise RuntimeError(f"Could not inspect Git objects (exit {process.returncode}).")
        position = 0
        while position < len(output):
            header_end = output.find(b"\n", position)
            if header_end < 0:
                raise RuntimeError("Malformed Git object scan output.")
            header = output[position:header_end].decode("ascii", errors="replace").split()
            position = header_end + 1
            if len(header) != 3:
                raise RuntimeError("Git object was unavailable during history scan.")
            object_id, kind, size_text = header
            size = int(size_text)
            content = output[position:position + size]
            position += size
            if output[position:position + 1] != b"\n":
                raise RuntimeError("Truncated Git object scan output.")
            position += 1
            if kind == "blob":
                path = objects.get(object_id, "(path not available)")
                for pattern_name, expression in PATTERNS.items():
                    if re.search(expression, content):
                        history["credential_pattern_flags"].append(
                            {"path": path, "category": pattern_name})
        # Commit identities can expose personal contact information. Count only.
        identities = subprocess.check_output(
            ["git", "log", "--all", "--format=%an%x00%ae%x00%cn%x00%ce"],
            cwd=ROOT,
        )
        history["distinct_author_or_committer_email_count"] = len(
            set(re.findall(rb"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", identities)))
        history["unique_reachable_objects_scanned"] = len(objects)
        history["event_log_or_packet_capture_path_count"] = len(subprocess.check_output(
            ["git", "rev-list", "--objects", "--all", "--", "*.evtx", "*.log",
             "*.pcap", "*.pcapng", "data/private/**"], cwd=ROOT
        ).decode(errors="replace").splitlines())
    print(json.dumps({"tracked_file_count": len(names), "credential_pattern_flags": flags,
                      "evidence_like_files": evidence, "development_url_paths": workspace_links,
                      "git_history": history,
                      "sensitive_values_or_addresses_printed": False,
                      "scope": "Tracked working-tree files and reachable history blobs when Git is available; "
                               "all files in a clean source export otherwise. Environment secrets are not read. "
                               "Heuristics cannot prove absence of credentials or personal data."}, indent=2))


if __name__ == "__main__":
    main()
