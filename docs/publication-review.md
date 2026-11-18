# Tracked-file publication review

Reviewed **2026-11-18 UTC** using `python scripts/review_public_files.py`.
This is limited publication triage, not a security certification.

## Actual results

- **289 tracked paths** examined in the working tree (the previous baseline
  before portfolio files were added was 283).
- **Zero matches** for the script's private-key headers, recognizable AWS/GitHub/
  provider-token patterns, quoted credential assignments and credential-bearing URLs.
- **Nine evidence-like files**, all in `data/synthetic/`: six CSV/JSONL files
  and three XML fixtures. No tracked `.evtx`, `.log`, `.pcap` or `.pcapng`
  evidence files were found.
- No tracked `.env` files or credential-named evidence files appeared in the
  filename review. No actual development `.replit.dev` URLs were found.
- The local Git refs contained 25 commits; 520 unique reachable Git objects
  were checked for the same credential patterns. No `.evtx`, `.log`, `.pcap`
  or `.pcapng` paths were found in history. One distinct author/committer email
  address is present in commit metadata; its value is deliberately not printed.
  That metadata and all earlier history are excluded from the clean source export.
- Synthetic fixtures have generated LAB accounts and documentation IPs. They
  are not asserted to represent real people or incident activity.
- No environment secret values were inspected or printed.

The script prints file paths and categories only, never a matched credential or
email address. It scans all unique reachable blob content and counts commit
identity emails without exposing them. New untracked files are not included in
the tracked-file count; rerun after staging the intended release files. The
curated source ZIP is 109 files and excludes Git metadata entirely; run the
script from the extracted source before creating a new repository.

## Publication decisions

Use a **fresh, curated repository** rather than pushing this workspace's entire
history. Exclude `.agents/`, `.local/`, `.replit`, artifact metadata, attachments,
unused JavaScript scaffolding, generated output, private evidence and browser
test material. These are workspace-specific or unnecessary, not automatically
proof of a credential leak. Do not delete them from the working application
solely to prepare the public snapshot.

`.gitignore`/`.replitignore` already exclude `generated-artifacts/` and
`data/private/`; ignore rules do not remove previously committed files.
Only intentionally reviewed synthetic screenshots/reports should be public.

## Limits and required human check

Pattern checks miss unknown token formats, secrets split across strings,
personal information in prose, images, binary files and earlier commits.
No OCR review, live credential validation or independent human privacy review
was performed. Zero pattern matches are not a guarantee that the repository is
safe to publish.

Before publication inspect the curated staged diff, choose a license, review
all images/exports and rerun the check. If a real credential is found, do not
publish: revoke/rotate it and address history exposure; deleting the current
line alone is insufficient. Follow [publication instructions](publication.md).
