# crashscope

Offline analyzer for JVM fatal crash logs. Point it at an `hs_err_pid*.log`
file, get a diagnosis: probable cause, evidence from the log, and a fix list.

    crashscope hs_err_pid4711.log

## Why

JVM crash logs are read by hand — the only offline analyzers are
enterprise-priced ($1,000+/mo, annual contracts). crashscope is a single
binary, runs fully offline, makes **no network calls**, and costs nothing.

## Usage

    crashscope [flags] <file>...

| Flag       | Effect                                        |
|------------|-----------------------------------------------|
| --json     | machine-readable JSON report                  |
| --verbose  | args, all native libraries, recent events     |
| --version  | print version                                 |

With multiple files, `--json` prints one JSON document per file, in order.

Exit codes (CI-friendly):
- `0` — cause identified (confidence ≥ medium)
- `1` — parsed, but pattern unrecognized
- `2` — unreadable file or not an hs_err log
- `3` — usage error

## Supported inputs

JDK 8, 11, 17, 21, 25 (latest) · linux, macOS, Windows · any vendor
(Temurin, Zulu, Corretto, Oracle, ...). Unknown sections are preserved,
never fatal.

## Known limitations

- `-XX:+SuppressFatalErrorMessage` and `-XX:+ShowMessageBoxOnError` suppress
  the hs_err file entirely — nothing to analyze.
- Frames marked "elided" by the JVM (`<...n frames...>`) are absent in the
  log and thus in our report.
- The bugs database is a curated list, not exhaustive.

## Privacy

crashscope runs fully offline and makes no network calls — no telemetry,
no uploads. It is a technical property of the code, not a legal guarantee.

## Install

Download a binary from [Releases](../../releases): linux/darwin/windows,
amd64/arm64. Homebrew tap and scoop manifest are planned.

## License

Apache-2.0. v0.1 is free and open; the pricing model for a future Pro
edition (report integrations, bugs-DB updates) is not decided yet.
