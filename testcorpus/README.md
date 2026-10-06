# Test corpus

## synthetic/
Synthetic hs_err files, hand-written from documented log shapes of
JDK 8/11/17/21/25 (linux + windows). Deterministic, safe to commit,
used by e2e tests. Paths/hostnames are fictional.

## real/  (add during/after Task 9)
Real hs_err files collected from public issue trackers. Before committing
any real file, sanitize it:
- replace real hostnames, usernames, IPs, company paths (sed over the file);
- remove anything after "Command Line:" if it contains credentials/tokens;
- record provenance in this README: source URL, JDK version, crash category.
Only attach files from public pages (GitHub issues, OpenJDK JBS, public gists).

## Generating more crashes locally
ycrash/buggyapp (Apache-2.0, github.com/ycrash/buggyapp) simulates
Java-level problems (OOM, SOE, CPU spike). Note: Java-level problems
produce hs_err files only with options like -XX:+ExitOnOutOfMemoryError
or when native code is involved; native crashes need JNI-based triggers.
