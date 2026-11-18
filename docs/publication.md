# GitHub publication instructions and release checklist

Nothing has been pushed or published by this preparation work. Suggested
repository name: **shield-56**. Start private while reviewing.

## Prepare a curated snapshot

Do not blindly push the existing workspace history. From the project root,
copy the Python product and reviewed documentation into a new directory:

```bash
DEST="../shield-56-public"
test ! -e "$DEST" || { echo "Choose a new empty destination"; exit 1; }
mkdir -p "$DEST/data" "$DEST/scripts"
cp README.md PROJECT_SPEC.md app.py pyproject.toml uv.lock requirements.txt .python-version "$DEST/"
cp -R incident_analyzer src tests docs evaluation .streamlit "$DEST/"
cp -R data/synthetic "$DEST/data/"
cp scripts/*.py scripts/*.sh scripts/*.ps1 "$DEST/scripts/"
find "$DEST" -type d -name __pycache__ -prune -exec rm -rf {} +
cd "$DEST"
printf '%s\n' '__pycache__/' '*.py[cod]' '.pytest_cache/' '.venv/' '.env' '.env.*' \
  '!.env.example' '.streamlit/secrets.toml' '.pythonlibs/' '.local/' '.agents/' \
  'generated-artifacts/' 'data/private/' 'attached_assets/' > .gitignore
git init -b main
```

These are instructions, not commands already executed. The cleanup targets only
Python caches in the new destination. Review copied content before proceeding.
If future docs add private material or new assets, update this selection.
Do not copy credentials, real logs or original evidence from a user session.
Inactive workspace artifacts and agent memory are deliberately excluded.

## Validate and review before committing

```bash
uv sync --frozen
uv run --frozen python -m pytest -q
uv run --frozen python scripts/validate_scenarios.py
uv run --frozen python scripts/verify_portfolio_case.py
uv run --frozen python scripts/benchmark.py
uv run --frozen bash scripts/run_streamlit.sh
# Stop the server after checking the synthetic walkthrough.
git add README.md PROJECT_SPEC.md app.py pyproject.toml uv.lock requirements.txt \
  .python-version .gitignore .streamlit incident_analyzer src tests docs evaluation data scripts
python scripts/review_public_files.py
git diff --cached --stat
git diff --cached --check
git diff --cached
```

Review the actual diff privately; do not paste credentials into an issue or chat.
The original workspace measurements remain historical. Record the fresh
environment's actual results rather than replacing numbers with estimates.
The curated snapshot/clean-machine commands have not yet been independently
verified; this is a release gate, not a completed test claim.

Choose a license deliberately and add its correct text to `LICENSE` before
public release; none is selected here. Review third-party notices and any
screenshot/media rights. Update README claims only to reflect verified work.

## Create and push the repository

Create an empty **private** repository in GitHub's UI, without a generated README.
Authenticate using your preferred Git credential manager or SSH agent; never
put a token in a remote URL, command example or repository.

```bash
git add LICENSE
git commit -m "Prepare Shield 56 synthetic investigation portfolio"
git remote add origin https://github.com/YOUR_USERNAME/shield-56.git
git push -u origin main
```

Replace `YOUR_USERNAME`. Inspect the rendered README, Mermaid diagram, local
links and screenshots on GitHub before making visibility public. Describe it
as an educational deterministic investigation tool. Suggested topics:
`cybersecurity`, `windows-event-log`, `python`, `streamlit`, `digital-forensics`.

After all checks and owner approval, choose a release tag matching the version
in `pyproject.toml` (currently 0.1.0). A sample command, **not yet executed**:

```bash
git tag -a v0.1.0 -m "Synthetic investigation portfolio release"
git push origin v0.1.0
```

Create a GitHub Release with the case-study/validation links and known
limitations. Attach only deliberately reviewed synthetic outputs; do not
upload the benchmark or arbitrary ZIPs just because they are available.

## Release checklist

- [ ] Owner reviewed source and can explain parsing, provenance, deduplication
  and each rule's boundary/limitations.
- [ ] Owner reviewed AI-assistance disclosure and personally reproduced the demo.
- [ ] License and third-party rights reviewed; LICENSE added.
- [ ] Curated snapshot excludes workspace history, credentials, private logs,
  agent memory and unreviewed screenshots.
- [ ] Staged-file triage rerun; all flags investigated privately.
- [ ] Fresh installation/startup/tests/scenario commands passed; actual results recorded.
- [ ] Benchmark environment and measurement scope remain attached to timing claims.
- [ ] README links/architecture diagram render correctly on GitHub.
- [ ] Screenshot checklist completed using synthetic-only evidence.
- [ ] Case report/ZIP opened and case identity verified.
- [ ] Seven-digit timestamp and Windows/OS-dialog limitations remain disclosed.
- [ ] No unmeasured accuracy, time-saved or real-incident outcome claims.
- [ ] Owner explicitly approved public visibility and release.

Human reviewer: **[not yet recorded]**  
Review date: **[not yet recorded]**  
Fresh-install environment/result: **[not yet measured]**
