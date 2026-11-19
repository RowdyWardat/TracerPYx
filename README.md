# TracerPyX

TracerPyX is an early-stage Python vulnerability reachability analyzer. It combines ZIP-based static source analysis, a project call graph, synthetic benchmark sink detection, OSV lookups for exact-pinned `requirements.txt` entries, and an optional scan-grounded AI assistant. It does not execute uploaded source or dependency manifests.

## Start locally on Windows

From the repository root in PowerShell:

```powershell
uv sync --extra test
uv run python -m uvicorn backend.main:app --reload
```

The API and interactive API docs are at `http://127.0.0.1:8000` and `http://127.0.0.1:8000/docs`.

In a second PowerShell window:

```powershell
cd frontend
npm.cmd install
npm.cmd run dev
```

Open `http://localhost:3000`. The frontend uses `http://localhost:8000` by default. Set `NEXT_PUBLIC_API_URL` before starting Next.js to point it elsewhere.

## Run tests

```powershell
uv run pytest -q
```

The benchmark fixtures live in `tests/fixtures`. Analysis reads source annotations and does not read their `ground_truth/expected_results.json`; tests load those answer keys only after the API analysis has produced results.

## AI assistant configuration

Copy `.env.example` to `.env`, set `OPENAI_API_KEY`, and start the backend with:

```powershell
uv run python -m uvicorn backend.main:app --reload --env-file .env
```

The API key is read on the backend only. The assistant sends a bounded scan context and recent conversation to the OpenAI Responses API with provider storage disabled. Without a key, chat returns a clear configuration error; no canned answer is used. Set `OPENAI_MODEL` to a model available to your account when needed.

## Analysis coverage and limits

- ZIP size and expanded size are bounded; unsafe paths are rejected; uploaded Python and setup scripts are never executed.
- Python files are parsed with `ast`; parse failures are surfaced as `UNCLASSIFIED` findings. Dynamic calls that cannot be resolved remain uncertain.
- Exact-pinned dependencies in `requirements.txt` are queried against OSV. Other detected manifest formats are reported, but dependency/version extraction for them is not yet implemented. A manifest version is a declared version, not proof of the installed runtime version.
- Synthetic advisories and `VULN-SINK` markers are visibly labeled. They are not real CVEs or upstream advisories.
- Call graphs and reachability are approximations. Framework registration, dynamic plugin loading, reflection, runtime configuration, and unrecognized entry points can produce uncertainty. `NOT REACHABLE` should be interpreted within the reported analyzed scope, not as proof that arbitrary runtime behavior cannot invoke a symbol.
- Analysis data is held in process memory and is lost when the backend restarts. This build has no production authentication or durable project storage; do not expose it as a multi-user service without adding those controls.

See `docs/architecture.md` for module responsibilities and API details.
