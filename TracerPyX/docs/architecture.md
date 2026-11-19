# TracerPyX Stage 1

FastAPI accepts ZIP uploads, checks archive limits and safe paths, parses Python source with `ast` without importing or executing it, then returns JSON. The call graph is approximate and intra-project only. Unresolved dispatch and parse errors yield UNCERTAIN.

`parser` extracts syntax facts; `graph` builds the call graph; `scanning_matcher` contains invented demo advisories; `engine` calculates verdicts; `reporter_command` normalizes JSON. The Next.js UI uses `/api/analyze`. AI features are deferred.

No live advisory feed, dependency installation, or external-package reachability proof is included. Results are not a production security assessment.
