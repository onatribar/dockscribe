# dockscribe

[![CI](https://github.com/onatribar/dockscribe/actions/workflows/ci.yml/badge.svg)](https://github.com/onatribar/dockscribe/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/onatribar/dockscribe.svg)](https://pkg.go.dev/github.com/onatribar/dockscribe)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

dockscribe is an offline CLI tool that audits Dockerfiles and Compose files, flags security and performance problems, and fixes the safe ones automatically.

```
$ dockscribe Dockerfile
File: Dockerfile (3 lines, 1 stage)

---

EXPLANATION
L1    Base image: node:18-alpine - starts build stage 0.
L2    Copies . into the image at ..
L3    Default startup command: ["node", "server.js"].

---

SECURITY
L3    [S001] [ERROR] Container runs as root - no non-root USER instruction found in the final stage.
      Add a USER instruction (e.g. `USER app`) before CMD/ENTRYPOINT so the container does not run as root at runtime.
L3    [S007] [INFO] No HEALTHCHECK defined.
      Add a HEALTHCHECK instruction so orchestrators can detect and route around an unhealthy container.
L1    [S018] [WARN] Base image "node:18-alpine" appears to be end-of-life.
      This Node.js release line is past its end-of-life date (nodejs.org releases) and receives no security patches. (This is a static, best-effort list and may be out of date - verify against the vendor's own support page.)
L1    [S019] [WARN] Broad COPY with no .dockerignore file.
      Without a .dockerignore, `COPY . .` sends everything in the build context to the daemon and into the image - including .git history, .env files, and credentials that happen to sit in the project directory. Add one that excludes at least .git, .env, and any local credential files.

---

PERFORMANCE
L1    [P005] [INFO] No multi-stage build detected.
      Build tooling and intermediate artifacts stay in the final image. Split into a `builder` stage and COPY only the built output into a slim final stage.
L1    [P011] [INFO] Broad COPY with no .dockerignore file.
      Without a .dockerignore, the entire build context (including node_modules, .git, and other large or generated directories) is sent to the daemon and can invalidate the build cache on every unrelated change.

---

Summary: 1 error, 2 warnings, 6 info
Score: 72/100 (C)
```

`--fix` applies the safe part of that automatically:

```
$ cat Dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl

$ dockscribe --fix Dockerfile
Fixed Dockerfile:
  L2: P002, P008
...
Score: 98/100 (A)

$ cat Dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install --no-install-recommends -y curl && rm -rf /var/lib/apt/lists/*
```

Compose files go through the identical pipeline, down to resolving a service's `build:` reference
against the actual Dockerfile it builds from.

## Install

Download a prebuilt binary from the [releases page](https://github.com/onatribar/dockscribe/releases) or build from source (requires Go 1.26+):

```sh
go install github.com/onatribar/dockscribe@latest
```

## Usage

```
SYNOPSIS
    dockscribe [options] [file|directory ...]

    No path given -> analyzes ./Dockerfile. A directory is scanned recursively
    for every Dockerfile/Compose file in it.

OPTIONS
    --format text|json
        Output format. Default: text.

    --severity info|warning|error
        Minimum severity to report. Default: info.

    --only security|performance
        Restrict to a single analysis category.

    --no-explain
        Skip the explanation pass; print findings only.

    --fail-on error|warning|info|never
        Minimum severity that makes dockscribe exit non-zero. Default: error.

    --fix
        Auto-fix a safe, unambiguous subset of findings in place, then report
        what's left. Only ever rewrites an instruction that occupies a single
        physical line - backslash continuations and RUN heredocs are left
        alone. Currently fixable: P002 (package-manager cache cleanup),
        P004 (ADD -> COPY), P008 (--no-install-recommends).

    --type dockerfile|compose
        Force the parser instead of guessing from the filename.

    --baseline <path>
        Only report findings not already recorded in this baseline file.

    --write-baseline <path>
        Write every current finding to this file as a new baseline, then
        exit 0.

    --version
        Print the version and git commit.

EXIT STATUS
    0   Nothing met the --fail-on threshold.
    1   Something did.
    2   dockscribe itself failed (bad flag, missing file, parse error)

EXAMPLES
    dockscribe                                 analyze ./Dockerfile
    dockscribe some-repo/                      scan a directory recursively
    dockscribe docker-compose.yml              Compose, detected by filename
    dockscribe --format json Dockerfile        machine-readable output for CI
    dockscribe --only security Dockerfile      skip the performance pass
    dockscribe --fail-on warning Dockerfile    exit 1 on warning-or-worse
    dockscribe --fix Dockerfile                auto-fix safe subset, report the rest
    dockscribe --write-baseline base.json .    accept every current finding
    dockscribe --baseline base.json .          only report NEW findings
```

## Rules

62 rules across three categories:
- Security (`S001`–`S026`, e.g. running as root, a secret left in a `builder` stage that leaks into the final image)
    - `pkg/analyzer/security/`
- Performance (`P001`–`P019`, e.g. a build stage that's pure wasted compute, a dependency cache invalidated on every change) 
    - `pkg/analyzer/performance/`
- Compose (`C001`–`C017`, e.g. the Docker socket bind-mounted into the container,
`privileged: true`)
    - `pkg/analyzer/compose/`

None of it is invented from scratch. It's checked against Docker's own
[build best-practices guide](https://docs.docker.com/build/building/best-practices/), the
[hadolint](https://github.com/hadolint/hadolint) `DL3xxx`/`DL4xxx` catalog, the
[OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html),
the CIS Docker Benchmark, the credential formats [gitleaks](https://github.com/gitleaks/gitleaks)
matches against, and [endoflife.date](https://endoflife.date/) for EOL cutoffs.

## Suppressing a finding

```dockerfile
# dockscribe-ignore=S001
USER root
```

The comment goes directly above the line it targets. A comma-separated list
(`# dockscribe-ignore=S011,P002`) or a wildcard (`*`) both work, in both Dockerfiles and Compose
files, and `--fix` respects them too. Most rules report on the instruction that triggered them,
but a few (`S001`, `S007`) report on the stage's last instruction instead, so check the finding's
`L<N>` before assuming a suppression didn't work.

A suppression naming a rule that never fires gets its own `U001` finding instead of silently doing
nothing forever (wildcards are exempt from this).

## Adopting dockscribe on an existing codebase

```sh
dockscribe --write-baseline .dockscribe-baseline.json .   # accept the current state
git add .dockscribe-baseline.json

# in CI from then on (only NEW findings gate the build):
dockscribe --baseline .dockscribe-baseline.json .
```

Matching ignores line number and uses `(file, rule, message)` with occurrence counting, so an
unrelated edit elsewhere in the file won't make an already-accepted finding look new.
`--write-baseline` always exits `0`.

## Why not just ask an LLM to read the Dockerfile?

Pasting a Dockerfile into a chat model answers a one-off question just fine. It's the wrong tool
to run on every commit, for a few concrete reasons.

1. dockscribe makes zero network calls. If the Dockerfile has internal image names, internal registry paths, or anything else that shouldn't leave the device, that's the whole reason this tool exists.

2. You can't gate a CI pipeline on an answer that drifts between runs or LLM versions, and nothing guarantees an agent reads the same file and prompt ("claude pls fix dockerfile make no mistakes") the same way twice. dockscribe is simply deterministic.

3. dockscribe runs with real filesystem access to the
build context, so a `COPY` source that doesn't exist, or a Compose `build.target` naming a stage
that isn't actaully in the Dockerfile it resolves to, gets caught directly. An agent reading pasted
text, with no files to check against, has no way to know either of those things is wrong. Sure,
an agent can be given filesystem access too, but handing an LLM agent broad read/write access to
your codebase is a security problem in its own right.

4. Every finding traces back to a rule you can actually read, unlike
a model's judgment call that can't be pinned down the same way. 

5. Fast.

None of this makes dockscribe smarter than an LLM at reading code it's never seen before. It's
built for a narrower job: a fast, reproducible, offline check you can run on every commit without a
second thought about where the file's contents just went. Under the hood that means
shell-grammar parsing of `RUN` instead of pattern matching (catching a relayed pipeline like
`curl ... | tee log | bash` the same way it catches `curl | bash` outright) secret detection by
actual value rather than variable name, and taint tracking across ARGs into ENV and RUN and across
build stages, so a secret left behind in a `builder` stage that leaks into the final image via
`COPY --from` gets caught even though no single instruction looks wrong on its own.

## Non-goals

- No LLM calls, kinda the whole point.
- Not a style-guide linter. That's [`hadolint`](https://github.com/hadolint/hadolint)'s job.
- Not a CVE/runtime container scanner. That's [`trivy`](https://github.com/aquasecurity/trivy)'s or [`grype`](https://github.com/anchore/grype)'s job.
- Doesn't build or run Docker images, only reads them and edits them in place with `--fix`.

`pkg/` is a plain importable Go library with no dependency on the CLI. If you want the analysis
engine in your own tool rather than this one, that's where it lives!

## Contributing

Want a rule that isn't here? Found a false-positive? Open an issue or PR, and I'll look into it!