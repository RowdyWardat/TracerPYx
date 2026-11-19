# TracerPyX architecture

## Existing ZIP analysis

`backend/main.py` accepts the original `/api/analyze` ZIP endpoint, enforces compressed/expanded size and path limits, skips symlinks, extracts to a temporary directory, and removes it in a `finally` block. It calls `backend/analyzer.py`, which runs the shared project pipeline:

1. `parser/python_parser.py` parses Python with `ast` and extracts source locations, imports, functions, decorators, and calls. Repository code is never imported or run.
2. `graph/builder.py` builds conservative intra-project call edges and recognized entry points (Flask, FastAPI, statically resolved Django URL routes, Celery task decorators, and functions named `main`). `engine/source_reachability.py` attaches call paths to local source-pattern findings. `engine/reachability.py` handles advisory symbol reachability.
3. `parser/security_patterns.py` reports heuristic source leads. Exact static versions declared in requirements/constraints `.txt` or `.in` files, pyproject.toml, Pipfile, Pipfile.lock, poetry.lock, uv.lock, setup.py, and setup.cfg are sent to OSV through `integrations/osv.py`. Dynamic declarations, non-exact versions, and non-registry sources are reported as warnings. This is not transitive dependency resolution and does not prove runtime installation or use. `backend/benchmark.py` and synthetic advisories continue to support the existing ZIP benchmark behavior.
4. Findings and diagnostics are normalized through `reporter_command/json_report.py`. ZIP results remain in the existing bounded process-memory store for the chat feature.

## GitHub PR analysis

`integrations/github_app.py` implements GitHub App OAuth user authorization, RS256 App JWT signing, installation-token creation, REST pagination, rate-limit/network retries, repository/PR reads, immutable commit-tree/blob reads, and optional review writes. `backend/github_pr_routes.py` owns authentication/session routes, discovery APIs, job lifecycle, result access, and explicit publishing endpoints. `backend/pr_storage.py` stores encrypted GitHub user credentials, job status, result cache, and per-session job access in SQLite. The frontend holds only an opaque HttpOnly cookie; no GitHub token is returned to JavaScript.

Analysis initiation resolves and records the repository ID plus exact base/head commit SHAs. The worker rechecks that the PR still points at that pair, retrieves all paginated changed-file metadata, and rejects PR file listings beyond GitHub's 3,000-file API cap. It traverses each commit tree without executing repository content and materializes relevant Python files, supported dependency manifests, and selected configuration files into bounded temporary directories. Tree, file, byte, and per-file limits are explicit; skipped symlinks, binary files, generated directories, unavailable patches, and unsupported config analysis are surfaced as warnings.

Both complete relevant source snapshots run through `backend/analyzer.py`, the same engine used by ZIP upload. GitHub unified diff hunks provide exact added/deleted line sets. Normalized finding identities and those line sets produce `introduced`, `worsened`, `fixed`, `pre_existing`, or `uncertain_attribution` classifications. A finding can be inline-commented only when its exact head line is in a GitHub-added hunk. Review comments use GitHub's `line` plus `side: RIGHT` anchor, carry stable TracerPyX markers, and update prior marked comments. The summary comment is similarly upserted. No repository writes occur until the user clicks Publish.

The report keeps pattern detection, graph reachability, taint, and exploitability separate. Current TracerPyX source checks and call graph do not implement value-flow taint tracking or establish exploitability. Configuration files are fetched and listed but are not interpreted by the shared analyzer. The report exposes these limits and does not claim tainted data reaches a sink.

## Storage and deployment boundary

SQLite is a durable single-node store. Credentials are Fernet-encrypted using `TRACERPYX_GITHUB_ENCRYPTION_KEY`; set a durable protected `TRACERPYX_DB_PATH` and keep the key in a deployment secret manager. The current job executor is an in-process two-worker pool. A multi-worker or horizontally scaled service needs a shared database, queue/worker deployment, per-user authorization, and managed key rotation before production hosting. GitHub App permissions should be Metadata read (implicit), Contents read, and Pull requests read/write only when review publishing is enabled. Private repositories and private fork heads must have the App installed; public repositories can be searched without installing the App.

## API routes

- Existing ZIP flow: `POST /api/analyze`.
- GitHub connection: `GET /api/github/auth/status`, `GET /api/github/auth/start`, `GET /api/github/auth/callback`, `POST /api/github/auth/disconnect`.
- Discovery: `GET /api/github/repositories`, `GET /api/github/repositories/{owner}/{repo}/pull-requests`, `GET /api/github/repositories/{owner}/{repo}/pull-requests/{number}`.
- Jobs and reports: `POST /api/github/analyze`, `GET /api/github/jobs/{job_id}`, `GET /api/github/jobs/{job_id}/result`, `GET /api/github/jobs/{job_id}/comparison`, `POST /api/github/jobs/{job_id}/cancel`.
- Optional publishing: `POST /api/github/jobs/{job_id}/publish`.
