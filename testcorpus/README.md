# Test corpus

## synthetic/
Synthetic hs_err files, hand-written from documented log shapes of
JDK 8/11/17/21/25 (linux + windows). Deterministic, safe to commit,
used by e2e tests. Paths/hostnames are fictional.

### Real-shape fixtures in synthetic/ (provenance)

Two files are derived from real hs_err logs posted on public GitHub issues.
They reproduce the exact structural shape of real logs (no `V M  A R G S` /
`M A P` section headers; `jvm_args:`, `java_command:` and the
`Dynamic libraries:` list as plain blocks inside `P R O C E S S`; real
"Current thread" variants). Sanitization per the rules below.

- `real_linux_jdk8u192.log`
  Source: https://github.com/broadinstitute/picard/issues/1501
  JDK: Oracle Java(TM) SE 1.8.0_192-b12, linux-amd64.
  Crash category: SIGSEGV inside libjvm (VMThread at safepoint,
  oop_oop_iterate_nv).
  Sanitization: `/cvmfs/soft.computecanada.ca/...` install paths replaced
  with fictional `/opt/java8` / `/opt/glibc-2.24` paths; host replaced with
  `cluster-node05`; snakemake console output that surrounded the paste
  (including the "Removing output files of failed job mark_duplicates ...
  corrupted:" line) omitted — it is not part of the hs_err file; some
  /proc/maps lines elided; the libjvm mapping line's file offset and the
  register values are reconstructed to stay consistent with the verified pc.
- `real_windows_corretto8.log`
  Source: https://github.com/corretto/corretto-8/issues/433
  JDK: Amazon Corretto / OpenJDK 1.8.0_342-b07, windows-amd64.
  Crash category: EXCEPTION_ACCESS_VIOLATION inside sigar-amd64-winnt.dll
  (SIGAR performance agent).
  Sanitization: hostname replaced with `WIN-RUNNODE01`; register values
  abbreviated; Dynamic libraries list shortened to the first verified
  entries plus the crashing dll (addresses verbatim from the source log);
  jvm.dll mapping line reconstructed (path pattern per the source
  install); SYSTEM section details kept generic; Time line fictionalized.

Also used as shape-verification sources (not committed as fixtures):
- https://github.com/rafaelabreu2/java/issues/1 (JDK 7u79, Linux —
  `JavaThread "C2 CompilerThread0" daemon [...]` thread line,
  `siginfo:si_signo=SIGSEGV:` shape)
- https://github.com/BTW-Community/BTW-Public/issues/715 (Temurin
  17.0.19+10, Windows — verified `S U M M A R Y` / `T H R E A D` /
  `P R O C E S S` / `S Y S T E M`-only layout and the
  `0xSTART - 0xEND path` Dynamic libraries lines)

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
