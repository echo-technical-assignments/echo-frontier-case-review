# Security Researcher take-home: Case Review

## The role

Our research team runs an automated vulnerability-research pipeline. It hunts for bugs in
open-source packages, writes up each one it believes is real as a **case**, and hands it to a
researcher for review. The researcher is the last check before a report goes to the maintainers.

In this assignment you are that researcher. You get two cases, each exactly as a reviewer first
saw it. Your job is to decide whether each one is ready to send, and to say why.

## What a reviewer can decide

- **Accept** the case as it is.
- **Accept with changes**: it's real, but something in the write-up, the proof or the score has
  to be fixed before it goes out.
- **Reject** it, with one reason:
  - `not_vulnerability`: it reproduces, but no security boundary is crossed
  - `not_reproducible`: the claimed behaviour doesn't happen
  - `already_public`: a CVE, GHSA or OSV entry already covers it
  - `duplicate`: another case already covers the same bug
  - `out_of_scope`: the code isn't in what users install (CI, docs, dev scripts)
  - `parked:lower_severity`: real, but much less severe than claimed, so it waits

## The cases

| Folder | Package | Claim | Filed as |
|---|---|---|---|
| [`case-a-gson/`](case-a-gson/) | `com.google.code.gson:gson` (Maven) | With no nesting-depth limit in `JsonReader`, a body of nested `[` characters grows the parser's state until the heap runs out. | High (7.5) |
| [`case-b-php-ftps/`](case-b-php-ftps/) | `php` (Debian package), `ext/ftp` | `ftp_ssl_connect()` + `ftp_login()` complete the TLS handshake without verifying the server certificate, so a machine-in-the-middle reads the FTP credentials. | High (7.4) |

Each case folder contains:

- `README.md`: the finding as the pipeline wrote it: what, where, impact, version range, CVSS
- `ADVISORY.md`: the draft report it would send to the maintainers
- `poc/`: the proof of concept, with `run.sh` and its own `README.md`
- `logs/`: the captured output of the PoC run (`baseline`) and the control run (`control`)
- `Dockerfile`: builds the pinned upstream version and runs the PoC, if you want to run it yourself

Treat everything in the case folders as the pipeline's claims, not as facts.

## What to answer, for each case

Review it as if you were the researcher who has to sign it off:

1. **Is it real?** Does the PoC test what the case says it tests, and do the logs show the
   claimed outcome?
2. **Is it a vulnerability?** Who is the attacker, what do they need, and what boundary do they
   cross? Read the project's own security policy and docs.
3. **Is it new?** Is it already public, or is it a known or documented behaviour?
4. **Is it scoped correctly?** Package, affected and fixed versions, preconditions, and whether
   the CVSS vector holds up.
5. **Your decision:** accept, accept with changes, or reject with one of the reasons above.
   Explain why.
6. **What you'd request:** the specific changes, re-runs or extra evidence you'd ask for before
   it goes out, in the order you'd ask.
7. **One change to the pipeline:** something that would have caught this earlier, or stopped it
   from reaching you.

## Deliverable

One review per case, using [`REVIEW_TEMPLATE.md`](REVIEW_TEMPLATE.md). About one page per case
is plenty. Submit them as Markdown or PDF.

We're more interested in how you think than in polished prose. A short review that catches the
one thing that matters beats a long one that restates the README.

## Sources and running things

- You may use any public source: OSV, GitHub advisories, NVD, upstream repositories and issue
  trackers, release notes, project docs.
- You may run the PoCs. Each case has a `Dockerfile`:

  ```sh
  docker build -t case-a-gson case-a-gson && docker run --rm case-a-gson
  docker build -t case-b-php-ftps case-b-php-ftps && docker run --rm case-b-php-ftps
  ```

  The PHP image compiles PHP from source (a few minutes). The gson run downloads Maven
  dependencies, so it needs network access. You can also change the PoCs and re-run them.
- Running anything is optional. Reading and reasoning is a valid review, as long as you **say
  what you ran and what you only read**. "I didn't verify X" is a fine answer. A confident guess
  presented as a fact is not.

## Time

Plan for roughly 2 to 3 hours for both cases. If you're running out of time, a clear decision
with the one or two reasons that matter is worth more than covering every question.
