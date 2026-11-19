# TracerPyX

TracerPyX is an early-stage Python vulnerability reachability analyzer. It combines ZIP-based static source analysis, a project call graph, synthetic benchmark sink detection, OSV lookups for exact static Python dependency versions, and an optional scan-grounded AI assistant. It does not execute uploaded source or dependency manifests.

## Start locally on Windows

From the repository root in PowerShell:

```powershell
cd TracerPyX
if (!(Test-Path .env)) { Copy-Item .env.example .env }
uv sync --extra test
uv run python -m uvicorn backend.main:app --reload --env-file .env
```

The API and interactive API docs are at `http://127.0.0.1:8000` and `http://127.0.0.1:8000/docs`.

In a second PowerShell window:

```powershell
cd TracerPyX/frontend
npm.cmd install
npm.cmd run dev
```

Open `http://localhost:3000`. The frontend uses `http://localhost:8000` by default. Set `NEXT_PUBLIC_API_URL` before starting Next.js to point it elsewhere.

## Run tests

```powershell
cd TracerPyX
uv run pytest -q
```

The benchmark fixtures live in `tests/fixtures`. Analysis reads source annotations and does not read their `ground_truth/expected_results.json`; tests load those answer keys only after the API analysis has produced results.

## AI assistant configuration

Copy `.env.example` to `.env`, set `OPENAI_API_KEY`, and start the backend with:

```powershell
uv run python -m uvicorn backend.main:app --reload --env-file .env
```

The API key is read on the backend only. The assistant sends a bounded scan context and recent conversation to the OpenAI Responses API with provider storage disabled. Without a key, chat returns a clear configuration error; no canned answer is used. Set `OPENAI_MODEL` to a model available to your account when needed.

## GitHub pull request analysis

TracerPyX can analyze a GitHub PR directly from its exact base and head commits. The worker fetches relevant Python and dependency context for both snapshots, reuses the same project analyzer as ZIP uploads, and maps findings against GitHub's diff hunks. Repository code is parsed statically and never executed. Publishing a summary or inline review is optional and requires a separate user action.

### Configure a GitHub App

Create a GitHub App for this TracerPyX deployment. Set its callback URL to `http://localhost:8000/api/github/auth/callback` for local work, or the deployed backend URL. Enable user authorization (OAuth) for the App. Grant Metadata read (implicit) and Contents read. Add Pull requests read; add Pull requests write only if users should be able to publish review comments. Install the App on repositories to analyze. To analyze a private fork PR, the App must be installed on the private head repository as well as the base repository.

Copy `TracerPyX/.env.example` to `TracerPyX/.env` and set these backend-only values:

- `GITHUB_APP_ID`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, and `GITHUB_APP_SLUG` from the App settings.
- `GITHUB_APP_PRIVATE_KEY_PATH` to the downloaded App PEM file. Keep it outside source control. `GITHUB_APP_PRIVATE_KEY_PEM` is also supported for secret-managed deployments.
- `TRACERPYX_GITHUB_ENCRYPTION_KEY` to a new Fernet key. Generate one with `uv run python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Back it up securely; changing it makes stored sessions unreadable and users must reconnect.
- `GITHUB_CALLBACK_URL`, `GITHUB_FRONTEND_URL`, `TRACERPYX_FRONTEND_ORIGIN`, and `TRACERPYX_DB_PATH` for your deployment. Set `GITHUB_COOKIE_SECURE=true` behind HTTPS; leave it false only for local HTTP development.

Start the backend with `uv run python -m uvicorn backend.main:app --reload --env-file .env` from `TracerPyX/` and start the frontend with `npm.cmd run dev` from `TracerPyX/frontend/`. In the dashboard, connect GitHub, search for an installed private repository or a public repository, select a PR, and click **Analyze PR**. The report displays actual worker stages, pinned SHAs, diff anchors, base/head attribution, dependency changes, coverage warnings, call paths, and remediation. Use **Refresh analysis** to bypass the same-commit result cache. To publish, select findings and click **Publish selected review**. Findings without valid added-line anchors are included only in the PR summary.

GitHub App permissions are scoped to installations. Public repository read/search works without installing the App. The feature uses encrypted SQLite sessions and a single-process two-worker pool; multi-worker hosting needs a shared queue/database and managed encryption-key lifecycle. The current detector does not implement taint tracking, complete framework route discovery, configuration-file analysis, or transitive dependency resolution. OSV checks cover exact static versions in requirements/constraints `.txt` and `.in` files, pyproject.toml, Pipfile, Pipfile.lock, poetry.lock, uv.lock, setup.py, and setup.cfg. Uncertain reachability and attribution must be reviewed as such.

See [the integration plan](TracerPyX/docs/github-pr-analysis-plan.md) and [the architecture reference](TracerPyX/docs/architecture.md) for details.

## Analysis coverage and limits

- ZIP size and expanded size are bounded; unsafe paths are rejected; uploaded Python and setup scripts are never executed. GitHub snapshots are pinned to exact SHAs, bounded by tree/file/byte/time limits, and also never executed.
- Python files are parsed with `ast`; parse failures are surfaced as `UNCLASSIFIED` findings. Dynamic calls that cannot be resolved remain uncertain.
- Exact static dependency versions in requirements/constraints `.txt` and `.in` files, pyproject.toml, Pipfile, Pipfile.lock, poetry.lock, uv.lock, setup.py, and setup.cfg are queried against OSV. Dynamic declarations and non-exact versions are reported as warnings. This does not resolve transitive dependencies, and a manifest version is a declared version, not proof of the installed runtime version.
- Synthetic advisories and `VULN-SINK` markers are visibly labeled. They are not real CVEs or upstream advisories.
- Call graphs and reachability are approximations. Framework registration, dynamic plugin loading, reflection, runtime configuration, and unrecognized entry points can produce uncertainty. `NOT REACHABLE` should be interpreted within the reported analyzed scope, not as proof that arbitrary runtime behavior cannot invoke a symbol.
- ZIP analysis and chat data remain in process memory. GitHub credentials, PR jobs, and PR results are stored in SQLite, with user tokens Fernet-encrypted at rest. The worker pool is in-process and single-node; horizontally scaled deployments need a shared queue/database, managed encryption-key rotation, and deployment-specific access controls.
- The source analyzer records static patterns and call-graph paths, not attacker-controlled value flow. It does not assert exploitability. Django URL routes, Flask/FastAPI route decorators and statically registered callbacks, Celery task decorators, and `main` functions are recognized, but other runtime registrations remain uncertain. Config files are fetched for context but not interpreted by the current analyzer.

See `docs/architecture.md` for module responsibilities and API details.
