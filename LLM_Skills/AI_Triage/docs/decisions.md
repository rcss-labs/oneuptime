# Decisions made during the build

AI Triage was built in five stages, from a plan per stage. Each task was implemented test-first, then read by a separate reviewer. Findings went back to an implementer for a fix, and the fix was re-reviewed, for up to five rounds per task. Open findings after round five were judged one by one. While the owner was away, the coordinating model took the decisions below. Each is a ruling written into the build ledgers at the time. The owner should confirm or reverse each one. Where a later ruling replaced an earlier one, both are kept and the earlier one is marked "Replaced by". Each entry has three lines: what was decided, why, and what it costs if it was wrong. The ledgers are git-ignored working files and are not part of the repository, so every entry is written to stand alone.

Entry numbers are stable names (G1, E4, R3 and so on) for use in other documents.

## Guard and platform

The guard is the hook that approves or refuses commands. "Platform" covers the permission policy, the installer and how the build itself was run.

#### G1. Branch
- **Decision:** Build on the existing branch `claude-skill` and do not create `feat/ai-triage-foundation`.
- **Why:** The owner had already switched to `claude-skill` before approving the plan.
- **Cost if wrong:** A branch rename.

#### G2. Parallel implementers
- **Decision:** Run two or three implementers at once, although the subagent-driven-development skill forbids it. Each track touches different files, commits only its own paths and runs only its own tests. The coordinating model runs the full suite after each wave.
- **Why:** The owner asked for parallel agents.
- **Cost if wrong:** A wave has to be run again if two tracks collide.

#### G3. One reviewer per wave
- **Decision:** Use one Opus reviewer per wave, who gives a verdict per task, instead of one reviewer per task.
- **Why:** The foundation code had been prototyped and tested before the build started.
- **Cost if wrong:** Less depth of review on individual tasks.

#### G4. Haiku transcribes stage 1
- **Decision:** Stage 1 implementers ran on Haiku and copied the plan's code with a helper (`extract_block.py`). The coordinating model compared the result with the prototype tree.
- **Why:** The plan carried complete, tested code, so the work was transcription.
- **Cost if wrong:** None recorded.

#### G5. Lint only the shell scripts that exist
- **Decision:** `run-tests.sh` runs the shell linter only on the shell scripts that exist.
- **Why:** The pre-build scan found that the plan would have failed the linter in tasks 1 to 12, before `install.sh` and the guard hook script existed.
- **Cost if wrong:** None.

#### G6. The live check is left to the owner
- **Decision:** Task 15, the live check of the installed skill, is not run by the build. Stage 3 must work whether or not skill hooks cover subagents.
- **Why:** It installs into the owner's home folder and needs an interactive Claude Code session.
- **Cost if wrong:** Analyst dispatch has to be redesigned if the chosen fallback does not hold.

#### G7. Plans for stages 2 to 5 without per-plan review
- **Decision:** The coordinating model wrote the plans for stages 2 to 5 at interface level and did not stop to have the owner review each.
- **Why:** The owner asked to hear back only when the full skill was done.
- **Cost if wrong:** Rework that the owner sees in the final report.

#### G8. No Ultracode switch
- **Decision:** Carry on with parallel subagents without Ultracode.
- **Why:** Ultracode is a toggle the user sets (`/effort ultracode on`) and the coordinating model cannot switch it.
- **Cost if wrong:** None.

#### G9. The guard allows only what it fully understands
- **Decision:** Redesign the guard around "allow only what is fully understood". It has a quote-aware tokenizer that refuses expansions, takes commands by bare name, knows the skill's own scripts from a fixed list, accepts pipe filters only in strict forms, accepts kubectl options only from an explicit list, and asks about AWS option abbreviations.
- **Why:** The first reviews showed that the first design could be shown one command while the shell ran another.
- **Cost if wrong:** More permission prompts for unusual command forms.

#### G10. A path ending in /aws is not aws
- **Decision:** `/usr/local/bin/aws` is no longer checked as the aws command. A test that the plan required was changed to match.
- **Why:** A path that ends in `/aws` can be any program.
- **Cost if wrong:** A prompt when the CLI is called by its full path.

#### G11. All-namespaces reads and the log tail bound
- **Decision:** `-A` stays an accepted namespace choice for kubectl, and `--tail` is bounded to 1 to 5000.
- **Why:** An explicit all-namespaces read is still a deliberate scope.
- **Cost if wrong:** Low.

#### G12. No API Gateway usage plans
- **Decision:** Remove usage plans from the API Gateway part of the AWS permission policy.
- **Why:** Usage plans expose API key values.
- **Cost if wrong:** The API Gateway playbook loses usage plan throttling detail.

#### G13. Fresh implementers for the first fixes
- **Decision:** The first review fixes were done by two fresh Sonnet implementers working from designer briefs, not by resuming the Haiku transcribers.
- **Why:** The transcribers held no design context.
- **Cost if wrong:** None.

#### G14. EKS cluster keys
- **Decision:** EKS cluster keys in the config accept upper case and underscores. This reverses part of the round 1 ruling.
- **Why:** The key is the real AWS cluster name.
- **Cost if wrong:** None.

#### G15. Unusual file descriptors
- **Decision:** A file descriptor other than 1 or 2 before a redirect makes the command unparseable, so the guard asks.
- **Why:** The guard has no reason to approve unusual descriptor plumbing. In zsh a digit glued to `&>` is a descriptor, so the scanner and the shell disagreed.
- **Cost if wrong:** A prompt for rare forms.

#### G16. The two stray folders stay
- **Decision:** Leave the two stray folders for the owner to remove.
- **Why:** During the red run of the installer fix, the old installer copied the skill into the repository, creating `skill/ai-triage/ai-triage/` and `skill/ai-triage/skills/`. The implementer's delete was denied by the permission system, and a denied action goes to the owner. The coordinating model did not do it on the implementer's behalf.
- **Cost if wrong:** The installer test file fails and the installer fix stays uncommitted until the owner acts.

#### G17. Redirects from a fixed list
- **Decision:** (Replaced in part by G19.) Accept redirects only in a fixed list of forms and treat everything else as unparseable.
- **Why:** Patching forms one at a time kept losing to differences between shells.
- **Cost if wrong:** Prompts for unusual redirects.

#### G18. The policy check uses an approved list
- **Decision:** The policy check requires every Allow action to be on an approved list that equals the shipped policy.
- **Why:** A list of forbidden actions can never be complete. The earlier check passed reads it did not name.
- **Cost if wrong:** One more place to edit when the policy grows.

#### G19. No input redirect at all
- **Decision:** Refuse every input redirect, accept unquoted word characters from an allow-list, and keep a generated differential test against real zsh in the suite.
- **Why:** Three rounds of patching one form at a time each left another difference, the last being zsh numeric globs.
- **Cost if wrong:** Prompts for unusual but harmless commands.

#### G20. File tools may not write script-owned files
- **Decision:** The guard denies the file tools (Write, Edit and the like) on the installed skill folder and on the case files that scripts own.
- **Why:** The scripts are the only writers. A hand edit could forge a label or an audit.
- **Cost if wrong:** Nothing in normal use.

#### G21. No aws command may write a local file
- **Decision:** AWS operations that stream output to a file are denied from a list generated from the CLI's own models, and no aws argument may be a local path.
- **Why:** An output file is a write on the engineer's machine. Some `get-` operations could overwrite the service map or a settings file.
- **Cost if wrong:** Nothing that a triage needs.

#### G22. grep is not an allowed filter
- **Decision:** `grep` leaves the allowed pipe filters. Preflight gains a shell-environment check for functions, aliases and options that change what runs. The zsh differential test gains a mode that sources a shell snapshot and evaluates, as Claude Code does.
- **Why:** Claude Code's shell snapshot defined `grep` as a function, so an approved `| grep` ran another program. The hook cannot see the shell's functions.
- **Cost if wrong:** Prompts for `| grep`. The skill text tells the agent to use `--query` and `jq`.

#### G23. The write tripwire reads parsed commands only
- **Decision:** The Bash tripwire for writes to protected files works on parsed command segments only.
- **Why:** The first version turned everyday commands into prompts. It is a tripwire and not a boundary.
- **Cost if wrong:** A hand edit written in a form the parser skips gets the normal permission prompt instead of a guard prompt.

#### G24. Paths allowed under CloudWatch Logs name options
- **Decision:** Path-like values are accepted only as the values of the CloudWatch Logs name options. Elsewhere the guard asks.
- **Why:** Log groups are often named after file paths, and denying them would stop a normal run.
- **Cost if wrong:** A slightly wider allow surface, never for positional arguments or home paths.

#### G25. Protected case files
- **Decision:** The guard denies Write and Edit tool calls into a case folder's `evidence/`, `judgments/`, `findings/checked.json` and `audit.json`, and the skill text forbids editing them. Later the list grew to include `incident.json` and `render.json`.
- **Why:** A digest cannot stop the author of both files. The guard and the rule make a forgery a visible act.
- **Cost if wrong:** Nothing in normal use.

#### G26. Interface-level plans
- **Decision:** The plans for stages 2 to 5 give interfaces, behaviour and required tests, not complete code.
- **Why:** Writing all the code twice adds nothing once implementers work test-first.
- **Cost if wrong:** More review effort per task.

#### G27. TypeSafe for red and done checks
- **Decision:** Implementers use a helper around the TypeSafe API (`ts_check.py`) for the red check and the done check of each task.
- **Why:** The owner's rules require TypeSafe for these decisions.
- **Cost if wrong:** A few API calls per task.

#### G28. run_kubectl checks at run time
- **Decision:** `run_kubectl` refuses at run time anything that `check_kubectl` does not allow.
- **Why:** `run_aws` has the same defence, added after a review found it ran anything.
- **Cost if wrong:** None.

#### G29. Case folders are only run folders
- **Decision:** A case folder is only `<cases_dir>/<incident>/<run>`, and every command checks this before it reads or writes.
- **Why:** The guard protects script-owned files at that depth only. A case copied elsewhere could be edited by hand and published with a forged label (final review A-C1).
- **Cost if wrong:** A case folder moved by hand no longer works.

#### G30. The hook decides connector calls
- **Decision:** The hook also decides connector calls. OneUptime write tools are denied, Slack tools that send or change anything ask, and a Confluence page write is allowed only with the exact body that the publish audit recorded.
- **Why:** "Ask before Slack" was only an instruction to the agent (A-I2, B-I-8).
- **Cost if wrong:** Tool names are matched by words, so an unusual connector name falls through to the normal prompt. Whether skill hooks fire inside subagents stays unverified, and analysts stay read-only by instruction.

#### G31. Replay is recorded and cannot be published
- **Decision:** Replay mode is recorded in `case.json`, in every evidence file and on the first line of the report, and publishing a replay case is refused. Replay itself is strict: an unrecorded call is an error and explicit empty answers are recorded.
- **Why:** A recording must not invent facts, and a report built from recordings must not reach Confluence (A-I3).
- **Cost if wrong:** None known.

#### G32. Policy trimmed, access check widened
- **Decision:** The usage-plans command leaves the API Gateway playbook, 18 policy actions that nothing used were removed (the policy now has 77), and every read that rests on `ViewOnlyAccess` is simulated by `verify_access.py`.
- **Why:** The document could not say what `ViewOnlyAccess` contains, so the owner's first verify run is made to answer it (A-I4, A-M4).
- **Cost if wrong:** A playbook lead that needed a removed action now needs a policy edit.

#### G33. More denials in the AWS guard
- **Decision:** `--cli-input-json` and `--cli-input-yaml` are denied, EC2 user data and DynamoDB stream records are denied, and the word after `aws` must be a real service name. A follow-up asks for reads that return launch templates or build environments and denies VPN connection reads.
- **Why:** Each of these could return secrets or hide a different command from the checker (A-I5).
- **Cost if wrong:** An occasional prompt for such a read.

#### G34. The installer stays blocked
- **Decision:** The fix that stops the installer copying the two stray folders waits for the owner's word to delete them. Keeping the raw intake file after a run (A-M9) is a stated limit.
- **Why:** The permission system denied the delete earlier, and a denied action goes to the owner (see G16).
- **Cost if wrong:** The installer would copy the stray folders as a nested second skill until the owner acts.

#### G35. One command wrapper and one exit-code table
- **Decision:** Every script's main goes through one wrapper (`triage/cli.py`) with one exit-code table. A config or map that is not UTF-8 is an invalid-file error, `opensearch_query.py` never overwrites evidence, `collect.py` and `opensearch_query.py` accept only run folders, and `case.py collect` exits non-zero when a collector failed. One owner made the change because every script's main was touched.
- **Why:** The final quality review found tracebacks, silent replacement of evidence files and inconsistent exit codes (C-I1, C-I4, C-M6).
- **Cost if wrong:** A broad but mechanical diff.

#### G36. Surviving mutations get tests
- **Decision:** The weak spots that the quality review found by mutation each get a test from their owner: a recommended action needs a confirmed cause, `read_audited` compares the audited hash, `map_suggest apply` keeps its three safety checks, the guard's name normalisation is pinned, and the audit scan writes invisible characters as escapes. `timeline.md` is dropped from the protected names, because `timeline.json` is the file that exists.
- **Why:** The tests caught 67 of 81 deliberate defects, and the others were real gaps.
- **Cost if wrong:** None.

#### G37. Quality items parked or left for last
- **Decision:** Explicit UTF-8 on every read and write (C-M5) is to be done last as one mechanical pass, when no owner is editing. Duplicated rules, private imports, dead code, the breadth of the hygiene test, suite cost and small items (C-M1, M2, M3, M8, M10, M11) are parked and stated, not fixed now. The note that plans 02 to 05 are superseded is added with this documentation pass.
- **Why:** None of them changes what a user meets, and each would be a refactor across other owners' files late in the round.
- **Cost if wrong:** The parked items remain. The UTF-8 pass has not landed yet.

## Evidence and collectors

#### E1. Unique evidence file names
- **Decision:** A cleaned file name suffix carries 6 hex characters of the raw name's sha256, the collection plan asserts that evidence file names are unique, and the evidence commands refuse to overwrite an existing file.
- **Why:** The file name is now the identity of every fact, because findings cite facts as file and fact id.
- **Cost if wrong:** None recorded.

#### E2. What was asked is hidden by content
- **Decision:** The text of what was asked is redacted by its content and never by the name of the target key.
- **Why:** The findings test sweep found that the access collector's `secret` target was masked by its key name, so that name was not recognised as asked text.
- **Cost if wrong:** None recorded.

#### E3. OpenSearch body allow-list
- **Decision:** The OpenSearch query check becomes an allow-list of the request shapes the tool builds.
- **Why:** A deny-list cannot keep up with the query language.
- **Cost if wrong:** No flexibility for ad hoc queries.

#### E4. Optional targets give a derived fact
- **Decision:** (Replaced by E5.) A collector with only optional targets, and none given, adds one derived fact.
- **Why:** Uniform behaviour across collectors.
- **Cost if wrong:** None.

#### E5. Optional targets are required as a group
- **Decision:** A collector whose optional targets are all missing is rejected up front, through a registry field `one_of` (exit code 4).
- **Why:** A missing input is a usage error, not evidence.
- **Cost if wrong:** None.

#### E6. RDS reads error logs and masks values
- **Decision:** (Replaced by E9.) RDS reads only error log files and masks quoted values and `=(...)` groups in every line.
- **Why:** Database logs carry row data.
- **Cost if wrong:** The slow-query log is not a source.

#### E7. CloudTrail window
- **Decision:** CloudTrail lookups cover the window start to five minutes after the incident start, when the start is known.
- **Why:** Later activity must not crowd out candidate causes.
- **Cost if wrong:** Changes made during the incident are not visible.

#### E8. Metric number format
- **Decision:** A Haiku agent updated the nine metric-format assertions as a mechanical edit, and the owner of the edge collector fixed the VPC summary length.
- **Why:** The number format ("17", not "17.0") is the ruled behaviour.
- **Cost if wrong:** None.

#### E9. RDS masks every quoted span
- **Decision:** (Replaced by E13.) RDS log lines mask every quoted span, parenthesised DETAIL text and digit runs of 5 or more.
- **Why:** The single-quote-only rule leaked card and phone numbers.
- **Cost if wrong:** Identifier names inside quotes are lost.

#### E10. EKS pod logs start at the window
- **Decision:** EKS pod logs use `--since-time` set to the window start with `--limit-bytes`, and no `--tail`.
- **Why:** `--tail` reads the end of the log, not the window.
- **Cost if wrong:** The end of a long window on a busy pod is cut. A fact in the evidence says so.

#### E11. WAF sampling covers managed groups
- **Decision:** WAF sampling also covers rule groups whose OverrideAction is None.
- **Why:** Managed rule groups had never been sampled.
- **Cost if wrong:** Up to five more sampling calls.

#### E12. Long lists live in data
- **Decision:** Long lists (ECS revision changes, VPC rules) go in the fact's `data` with a count in the summary.
- **Why:** The 500-character summary cap cut them silently.
- **Cost if wrong:** None recorded.

#### E13. RDS keeps identifiers after keywords
- **Decision:** (Replaced by E16.) RDS keeps identifier-shaped quoted spans after a fixed list of words, masks every digit run of 3 or more except engine error codes, and masks `user=` in log prefixes. Free text that an application raises inside the database is a stated limit.
- **Why:** Masking everything lost the relation and constraint names that an engineer needs.
- **Cost if wrong:** Application text inside the database log can be shown.

#### E14. RDS file reading
- **Decision:** RDS reads at most 6 log files, the one that covers the onset first, and never says that no error log exists unless the complete listing shows it.
- **Why:** The review found that only three files were read, so a partial look could be reported as an absence of errors.
- **Cost if wrong:** None recorded.

#### E15. EKS keeps selected lines
- **Decision:** (Replaced in part by E17.) EKS keeps the first 20 in-window lines plus up to 30 error-looking lines in `data["lines"]`.
- **Why:** The review found that the wrong lines were kept after a cut.
- **Cost if wrong:** Some relevant lines are not kept.

#### E16. RDS masking without quote matching
- **Decision:** RDS masking no longer matches quotes. At any quote character it either keeps one keyword-preceded identifier or masks the rest of the line. Digit runs of 2 or more are masked, and users are masked in every prefix form.
- **Why:** Three rounds of quote matching each left a way to confuse it.
- **Cost if wrong:** The tail of some error lines is lost.

#### E17. Onset and error lines
- **Decision:** The RDS onset is the incident start, and 40 lines are kept around it with counts. EKS keeps strong error lines first and counts repeats.
- **Why:** The review found the onset taken from the window start and a silent 20-line cap.
- **Cost if wrong:** None recorded.

#### E18. Dated facts carry their time
- **Decision:** A dated event read from a resource's own data carries its time. The certificate expiry fact is `incident_time` when `NotAfter` lies in the window.
- **Why:** The expiry fact had no time, so the timing gate always failed and an expired certificate could never be a confirmed cause.
- **Cost if wrong:** None.

#### E19. ECR states the repository name only
- **Decision:** The ECR collector states the repository name and registry id only. It makes no extra `describe-repositories` call for the ARN.
- **Why:** The call would need a permission that the policy was not checked for.
- **Cost if wrong:** An ARN the engineer can derive.

#### E20. Metric points are sorted
- **Decision:** (Replaced by E22.) Metric facts sort their points and give the earliest peak.
- **Why:** Peaks were reported from unsorted data.
- **Cost if wrong:** None.

#### E21. Change lookups also go by event source
- **Decision:** CloudTrail change lookups also go by event source, and the absence fact says only what was asked.
- **Why:** A lookup by name alone missed changes made through another resource name, and an absence fact claimed more than the lookup showed (B-I-3).
- **Cost if wrong:** Up to 10 more pages per source. The assumption about event-source short names is unverified until the live check.

#### E22. Metric facts say lowest, highest and the first departure
- **Decision:** Metric summaries state the lowest and highest values with their times, compare the incident part with the same time last week, and name the first point where the series left its baseline.
- **Why:** A peak alone hid a series that had dropped, and it gave no reference to say whether the value was unusual (B-I-1).
- **Cost if wrong:** Every recorded metric summary changed wording.

#### E23. The plan uses the new map keys and one level of dependencies
- **Decision:** The collection plan runs `alarms`, `ecr` and `opensearch_domain` from the new map keys, and a light set (changes, and alarms when mapped) for each direct dependency in `depends_on`. `vpc` and `access` stay lead-following, and the playbooks say so.
- **Why:** The collectors existed but nothing ran them (B-I-2).
- **Cost if wrong:** More calls per run. Dependency depth is one only.

#### E24. Discovery saves its own output
- **Decision:** `discover.py --save` writes its output under the intake folder and still saves when nothing was found, with what it tried. Dead ends are named in the skill text and in the ask list.
- **Why:** The agent had to save discovery output by a Write call that the guard did not expect (B-I-5).
- **Cost if wrong:** None.

#### E25. A failed read never becomes an absence
- **Decision:** A property test across all collectors checks that a failed read never produces an absence statement. The access collector said a failed role policy listing could not be read.
- **Why:** A statement that nothing was found is evidence, and a failed read is not (C-I2).
- **Cost if wrong:** The test does not probe kubectl calls, and for alarms, ecr and logs it covers the first call only.

#### E26. Collectors state resource ARNs
- **Decision:** Collectors state the ARNs of their resources from the answers they already read.
- **Why:** A work order without exact identifiers is not actionable (from the instruction-text test log).
- **Cost if wrong:** None.

#### E27. Collection runs with one command
- **Decision:** `case.py collect` runs the whole collection plan, at most four collectors at a time, and prints what each wrote.
- **Why:** Ten copied commands per run invite mistakes and permission prompts (from the instruction-text test log).
- **Cost if wrong:** A failed collector shows in the exit code and in the counts, not only in a file.

## Redaction

#### R1. Secret names by components
- **Decision:** A key is secret or not by its name components, with an exception for metadata suffixes. This replaces the plan's substring rule.
- **Why:** The substring rule both leaked secrets and hid ordinary keys.
- **Cost if wrong:** A longer rule to maintain.

#### R2. Reduced environment values
- **Decision:** (Replaced by R3.) Environment values are stored in a reduced form: only the scheme and host of a URL, hostnames, numbers and short lower-case settings. Everything else is hidden. The alternative was to store names only.
- **Why:** The owner's goal includes finding "the app points at Y but it is on Z".
- **Cost if wrong:** Some detail in paths and query strings.

#### R3. Show only plainly harmless values
- **Decision:** (Replaced by R5. Amends R2.) A value is shown only when it is plainly not a secret: short words, short numbers, booleans and validated hosts. Names with components such as salt, hash, pin, seed or jwt are always hidden.
- **Why:** The review found secret-looking values shown under innocent names such as SALT.
- **Cost if wrong:** Long or mixed settings are hidden.

#### R4. Embedded data in log text
- **Decision:** `text()` parses embedded JSON and Python-literal spans in log lines and redacts them structurally.
- **Why:** Log lines carry pretty-printed and repr data that no pattern can cover.
- **Cost if wrong:** The original formatting of the embedded span is lost.

#### R5. Values shown by setting name
- **Decision:** (Replaced by R9.) Environment values are shown by name. A fixed list of setting-like name words unlocks plain values. Other names show only booleans, URL origins, dotted hosts, IPv4 addresses and regions.
- **Why:** A hand-typed password under an innocent name must not reach a published report.
- **Cost if wrong:** Some harmless values are hidden.

#### R6. Hostnames under unusual names
- **Decision:** Under a name that is not setting-like, a dotted hostname needs three or more labels to be shown.
- **Why:** The shapes `first.last` and `user:pin` have two labels.
- **Cost if wrong:** Two-label hosts under odd names are hidden.

#### R7. Redaction round 4 redesign
- **Decision:** Redaction round 4 went to a fresh Opus implementer with a wider design. The module never raises, normalises text before matching, and fails closed on key-like tokens in free text with stable placeholders. It has false-positive rules and a corpus test built at run time.
- **Why:** Patching shapes one by one had not converged.
- **Cost if wrong:** Some harmless long tokens are masked.

#### R8. Public IP addresses are masked
- **Decision:** (Corrected after the final review: this entry first said that IP addresses are not masked, which the code never did.) Public IPv4 addresses are masked as `<IP-n>`, and the numbering restarts in each evidence file. Private addresses stay readable. Phone numbers with a leading `+` are masked. IPv6 addresses are not.
- **Why:** A public page is safer without public addresses, and private addresses are what an engineer needs to follow a request inside the network.
- **Cost if wrong:** "The app points to y but it is on z" reads as two masks when y and z are both public addresses.

#### R9. Values shown by value type
- **Decision:** Environment values are shown by value type for each kind of setting name. The secret-name check has one source, `redact.looks_secret_key`, which strips digits and knows abbreviations. Under a secret-like name only a URL origin is shown.
- **Why:** Three rounds of deny-list patches kept leaking.
- **Cost if wrong:** Option strings and unusual settings are hidden.

#### R10. The kind comes from the last name part
- **Decision:** The kind of a setting is taken from the last part of its name only.
- **Why:** `LDAP_SERVER_BIND` showed a plain word as if it were a host.
- **Cost if wrong:** None.

#### R11. Round 5 and its stated limit
- **Decision:** Round 5 fixed a bypass (a two-item list), the cost (2 seconds per MB, plus a 5 second budget that fails closed), the name rules and the listed shapes. Keeping placeholders consistent across files is a stated limit.
- **Why:** A new placeholder format would touch every consumer in the last round.
- **Cost if wrong:** The same secret can get different placeholders in different files.

#### R12. License as a secret word
- **Decision:** "License" is a secret word as the last part of a name or next to "key", and not before a qualifier ending. This corrects the coordinating model's own earlier rule.
- **Why:** `NEW_RELIC_LICENSE` holds a key. `PRIVATE` and `CODE` alone are not secret names, and `PINCODE` is.
- **Cost if wrong:** None.

#### R13. A short follow-up closes redaction
- **Decision:** A short follow-up, not a fix round, took the reviewer's first choice (user information in URLs without a scheme), a prose exemption, three names, Windows shapes and secret-name table cells. Everything else in that review is a stated limit.
- **Why:** The round limit was reached, and no open item was judged load-bearing.
- **Cost if wrong:** A leak in one of the stated limits (see the README).

#### R14. A value after a secret word is masked whatever its shape
- **Decision:** A value after a secret word is masked in the redactor whatever its shape. The second detector independently flags values of 16 or more characters after a secret word. What stays readable: values under 8 characters, a single word of up to 15 letters, numbers of up to 14 digits, letter-only names, ARNs and passphrases written as words joined by dashes.
- **Why:** A 32-hex key and a UUID passed all three layers and would have reached the scoring service (A-C2).
- **Cost if wrong:** Some resource names after "key" or "secret" are masked or prompt at publish time. UUID KMS key ids are over-masked. The readable shapes above are a stated limit.

## Findings

#### F1. Qualified citations
- **Decision:** Findings cite facts as `<evidence file stem>:<fact id>`, and a bare id that is ambiguous is refused.
- **Why:** Fact ids repeat across the evidence files of one collector.
- **Cost if wrong:** Longer citations.

#### F2. Excerpt length
- **Decision:** An excerpt must be at least 12 characters unless it equals a whole string value, and provenance is checked on the facts that contain the excerpt.
- **Why:** A review finding on excerpt length. The ledger gives no further reason.
- **Cost if wrong:** An honest short quote is refused.

#### F3. Ids and summaries are not redacted again
- **Decision:** Fact ids and fact summaries in `checked.json` are never redacted.
- **Why:** They come from evidence that is already redacted, and an id is an identifier. The redactor had mangled qualified ids.
- **Cost if wrong:** None.

#### F4. Data keys that cannot be quoted
- **Decision:** (Replaced by F5.) Strings under the data keys `asked`, `query`, `index`, `filters`, `window`, `method`, `command`, `request`, `target` and `parameters` are never quotable.
- **Why:** They describe what was asked, not what was found. A review showed that the OpenSearch query the agent typed was accepted as a quote.
- **Cost if wrong:** None recorded.

#### F5. Structural split of asked text
- **Decision:** Every evidence file records what was asked, in a top-level `asked` written by the evidence layer (and `data["asked"]` per fact in the OpenSearch tool). The findings check skips only `asked`, refuses an excerpt contained in an asked string, and summaries do not repeat free-text input. A test proves it end to end.
- **Why:** A deny-list of keys cannot cover summaries.
- **Cost if wrong:** Findings must quote found text, not names.

#### F6. Twelve characters of found text
- **Decision:** After asked strings are removed, at least 12 non-space characters of other text must remain in an excerpt.
- **Why:** An asked name plus one word of collector wording was still accepted.
- **Cost if wrong:** Collector wording of 12 or more characters around an asked name counts as found text. The judging step has to catch a quote that does not support its claim.

#### F7. Asked text of a search
- **Decision:** The per-fact asked text of a search (its query and filters) is checked by containment only. File-level asked text (collector targets) keeps the cut rule.
- **Why:** An answer to a search legitimately contains the search terms.
- **Cost if wrong:** A search hit that only repeats the query text may be accepted as found text, so the judging step has to catch it.

#### F8. The judge sees what was asked
- **Decision:** `checked.json` gains `asked` for each cited fact, and the judge's states show it, with one added sentence in the question text.
- **Why:** The citation check cannot judge meaning. A real quote such as "4000 documents matched" passed for a claim that the query could not support, so the judge must be able to see the question.
- **Cost if wrong:** None.

#### F9. Registry sweep moves to real evidence
- **Decision:** Coverage of found answers under the asked rule moves to the replay pipeline test, which uses real evidence. The registry sweep must fail on a collector that wrote no fact, unless that case is listed with a reason.
- **Why:** The sweep asserted nothing when a collector wrote no fact (19 of 21 in the error variant).
- **Cost if wrong:** A new collector needs an entry in the sweep.

#### F10. Any string in data may be quoted
- **Decision:** A finding may quote any string in a fact's `data`, not only its summary and excerpt. `checked.json` stores the matched string. F4 and F5 later removed what was asked from this.
- **Why:** Long lists live in `data` since the 500-character summary cap.
- **Cost if wrong:** A wider search in `findings.py`.

#### F11. Comma-separated targets
- **Decision:** `target_items` also itemises any value that contains a comma. No `list_targets` field is added to the registry.
- **Why:** It only makes the findings check stricter.
- **Cost if wrong:** None.

#### F12. The judge sees the quoted passage
- **Decision:** Every evidence item in a finding's state carries `quoted`, the checked matched text.
- **Why:** The judge was sent each cited fact's summary and excerpt, not the passage the finding quoted, so a clearly evidenced cause stayed probable in a live run.
- **Cost if wrong:** Up to 500 characters more per finding.

## Judging

#### J1. Digest of whole objects
- **Decision:** The digest covers the whole cause and action objects, minus an explicit list of fields written after judging, plus a draft digest over the symptoms, scope, set of cause ids, cited findings and case identity.
- **Why:** A list of digested fields keeps missing one.
- **Cost if wrong:** None recorded. See J11 for the price of editing.

#### J2. No label without a summary
- **Decision:** No label above `candidate` is accepted without a summary written by the judging code.
- **Why:** Deleting the summary lifted a candidate to `probable`.
- **Cost if wrong:** None.

#### J3. Digests in summary.json
- **Decision:** `summary.json` stores a sha256 digest of the judged fields of each cause and action (module `triage/digest.py`). Report validation caps anything whose digest no longer matches.
- **Why:** An edited cause must not keep "confirmed".
- **Cost if wrong:** Judging has to be run again after any edit.

#### J4. Every answer is validated
- **Decision:** The TypeSafe client validates every answer and raises `JudgeUnavailable(MalformedAnswer)`. Comparisons fail closed.
- **Why:** A review found that answers were never validated.
- **Cost if wrong:** A malformed answer from the service stops judging.

#### J5. The ranking order is reversed
- **Decision:** In the second ranking request the whole option list is reversed, fallback included. This replaces the plan's "fallback always last".
- **Why:** Position bias is then tested even with one cause.
- **Cost if wrong:** None.

#### J6. Done checks skip the live test
- **Decision:** Done checks run with the environment-gated live TypeSafe test deselected.
- **Why:** TypeSafe reads "1 skipped" literally as "not all passed".
- **Cost if wrong:** Nothing. The live test runs once, in the final smoke test.

#### J7. Digests cover whole objects (restated)
- **Decision:** The judging ledger restates J1: digests cover whole objects minus a list of post-judging fields, the whole cited finding entry, and a draft digest with the case identity.
- **Why:** The same reason as J1.
- **Cost if wrong:** As J1.

#### J8. Malformed answers and outages
- **Decision:** A `MalformedAnswer` is a failed run in which every label is `candidate`. An unavailable service part-way through keeps ruled-out causes at `candidate`.
- **Why:** A malformed answer part-way had lifted a ruled-out cause to `probable`.
- **Cost if wrong:** A bad answer costs a full judging run.

#### J9. Uncertain contradictions cap a cause
- **Decision:** An uncertain contradicting finding caps the cause at `probable`.
- **Why:** The ledger gives no separate reason. A cause that something may contradict should not be stronger than `probable`.
- **Cost if wrong:** A true cause stays at `probable`.

#### J10. Failed and unavailable runs differ
- **Decision:** A failed run exits 1 and writes a `typesafe` value that starts with "failed: ". An unavailable service keeps exit 0.
- **Why:** So that scripts and the report can tell a broken judging run from a missing service.
- **Cost if wrong:** None recorded.

#### J11. Any action edit means judging again
- **Decision:** The whole-object digest stays. Editing any action field after judging means judging again.
- **Why:** A looser rule would let a changed action keep its judged label.
- **Cost if wrong:** A paid re-run for a cosmetic edit.

#### J12. The timing gate has no lower bound inside the window
- **Decision:** The timing gate keeps no lower bound inside the window.
- **Why:** A cause may precede its effect by any amount of time.
- **Cost if wrong:** A cause far earlier in the window is not penalised for timing.

#### J13. The evidence gate stays strict
- **Decision:** Every listed supporting finding must be verified. The skill text gives the agent the way out: rewrite an uncertain finding's claim to what its quote says, or take it off the cause's list, and judge again, at most twice.
- **Why:** Listing only solid support is the behaviour wanted.
- **Cost if wrong:** Up to two more judging runs.

## Report

#### RP1. Safe ids, quiet messages, stale outputs
- **Decision:** Report ids match a fixed pattern, problem messages never repeat report values, and a failed render renames the old outputs to `*.stale`.
- **Why:** Raw fact ids and times could forge headings, messages repeated report text, and a render crash left old outputs looking current.
- **Cost if wrong:** None.

#### RP2. The render marker
- **Decision:** The render marker (`render.json`) records the hashes of its inputs (`report.json`, the summary and `checked.json`). Publishing refuses unless the marker is current.
- **Why:** After re-judging with lower labels, an earlier `report.md` with stronger labels stayed in place and could be published.
- **Cost if wrong:** A render before every publish.

#### RP3. The same implementer for round four
- **Decision:** The fourth report fix round stays with the same implementer.
- **Why:** It was a gap in the marker added one round earlier, not a repeated failure, so the escalation rule did not apply.
- **Cost if wrong:** None.

#### RP4. No absolute local paths
- **Decision:** The report and work order never print an absolute local path. The case folder is shown relative to the cases root.
- **Why:** The report published the home folder and tripped the audit.
- **Cost if wrong:** None.

#### RP5. Report free text may not state a label
- **Decision:** Report free text is covered by the draft digest and may not state a label. "What broke" on the page is the judged top cause. The author's own sentences are printed under "author's summary, not scored". No new scored question was added for the summary.
- **Why:** One more judgment kind in a final fix round is more risk than the deterministic rule (A-I1, B-I-7).
- **Cost if wrong:** A misleading but label-free author sentence can still be printed, under that heading.

#### RP6. Quotes and causes on the page and in the work order
- **Decision:** The report prints each finding's quote and both the summary and the excerpt of each cited fact. The work order carries each action's cause, the cited claims and the quotes.
- **Why:** A reader could not check a claim without opening the evidence (B-I-6, B-I-9).
- **Cost if wrong:** A longer report.

## Publishing

#### P1. A second, independent detector
- **Decision:** The publish audit gets an independent second detector (`triage/audit_scan.py`), written by a different implementer who does not read `redact.py`.
- **Why:** The same rules applied twice catch nothing new.
- **Cost if wrong:** None recorded.

#### P2. Audit the exact bytes
- **Decision:** `confluence_request` audits the exact bytes it names, refuses symbolic links and records sha256 values. File times are no longer trusted.
- **Why:** A review found a way around the Confluence gate.
- **Cost if wrong:** One more audit pass per publish.

#### P3. Editing an empty services line
- **Decision:** An empty `services:` mapping is rewritten on its own line only. When that cannot be done exactly, `apply` refuses and prints the block.
- **Why:** Changes to the engineer's service map must be exact.
- **Cost if wrong:** The engineer pastes the block by hand.

#### P4. Minor follow-up without its own review
- **Decision:** A short follow-up closes nine small items of the publish and map reviews and gets no separate re-review. The final whole-branch review covers it.
- **Why:** The items are small and mechanical.
- **Cost if wrong:** A late finding if one of them is wrong.

#### P5. Overriding a false alarm
- **Decision:** Both detectors must be clean. A false positive can be overridden only with `--accept-hits=<sha256 of the audited bytes>`, and the guard always asks the engineer for a command that carries this flag.
- **Why:** An unattended run must not publish over a hit.
- **Cost if wrong:** A prompt whenever a detector is wrong.

#### P6. Account ids in the report
- **Decision:** The configured triage account ids are allowed in `report.md` and `work-order.json`. Any other 12-digit number is a hit. The Slack message and the page title allow none.
- **Why:** The engineer and the work order need the account to act, and the ids are already in the engineer's own config.
- **Cost if wrong:** Account ids appear on an internal Confluence page.

#### P7. One digest for the whole set
- **Decision:** One digest of the whole audited set is the value for `--accept-hits`.
- **Why:** The first design could not cover two files.
- **Cost if wrong:** None.

#### P8. When a 40-hex string is allowed
- **Decision:** A run of 40 hex characters is exempt only when its line has a word such as commit, revision, git, sha, image, tag, version, build or deploy.
- **Why:** Git commit and image ids look like keys and would stop every publish. Limiting the exemption to such lines keeps a bare 40-hex secret a hit.
- **Cost if wrong:** A secret placed on such a line passes this detector.

#### P9. The residue rule
- **Decision:** Adopt the residue rule for the "mostly words" cut. Context words must be whole words and never exempt a line that has a secret word.
- **Why:** Matching context words as substrings let a 40-hex secret pass.
- **Cost if wrong:** Some random lower-case tokens under about 40 characters are missed.

#### P10. Approval without a last measurement
- **Decision:** After round 3 the detector was approved on its tests and the final whole-branch review, without another full measurement.
- **Why:** The reviewer's open items were one condition and a list of exemptions.
- **Cost if wrong:** A late finding if an exemption is wrong.

#### P11. The publish request names the body format and the default channel
- **Decision:** The Confluence request names the body format and the Slack default channel. After publishing, the agent reads the page back and saves the body, and `publish.py verify-confluence` compares its hash with the audited report.
- **Why:** The agent could not know that the page it wrote was the audited text (B-I-8).
- **Cost if wrong:** Unverified until the live check, because the connector cannot be exercised here. There is no `confluence.space_id` config field yet; the request prints a note.

## Skill text

These come from the test log of the instruction files, not from the ledgers' ruling lines. The instructions were written after two baseline runs without the skill.

#### S1. A recipe with exact formats
- **Decision:** `SKILL.md` is a positive 13-step recipe, and `reference/formats.md` shows the exact format of every file the agent writes, with prohibitions only where a baseline or review showed a real failure.
- **Why:** The baseline run did most things well but stopped where the formats were missing: no findings files, no `report.json`, no judging, a percentage from its own reading, no analysts, no audit.
- **Cost if wrong:** An agent that ignores the recipe gives a handover without labels.

#### S2. Script-owned files are never edited by hand
- **Decision:** The skill forbids hand edits of script-owned files. An audit hit is fixed at its source in `report.json`, or the run stops and asks. `--accept-hits` belongs to the engineer.
- **Why:** In a baseline run the agent said it would hand-redact `report.md` and scan again, which breaks the design.
- **Cost if wrong:** A hand-edited report can be published without its audit meaning anything.

#### S3. The text is tied to the code by tests
- **Decision:** `tests/test_playbooks.py`, `tests/test_skill_text.py` and `tests/test_reference_formats.py` check the instruction files against the code: structure, collector names and target keys, that every aws and kubectl command in the text is approved by the real guard, and that the prompts agree with the domain map.
- **Why:** The playbook writers found several gaps between what the collectors did and what the text could say.
- **Cost if wrong:** The text and the collectors drift apart when a test is skipped.

#### S4. Intake has its own reference file
- **Decision:** `reference/intake.md` maps OneUptime tool results to the incident file, written from the reviewer's field mapping and marked as not run against a live OneUptime.
- **Why:** The agent had no source for which tool gave which field (B-I-4).
- **Cost if wrong:** Two details are unconfirmed: the monitor URL inside `monitorSteps` and the time field of a public note.

## Open items

These need the owner.

- **Two stray folders and the installer fix.** `skill/ai-triage/ai-triage/` and `skill/ai-triage/skills/` are untracked folders that an earlier installer run created inside the repository (G16, G34). The owner removes them. Until then `install.sh` and `tests/test_install.py` hold an uncommitted fix for installing through a path that contains a symbolic link, and that fix has not been verified.
- **The live check.** Install the skill into a real home folder and run it in Claude Code against real accounts. It has to settle:
  - a run against real AWS accounts and a real OneUptime, including the intake shapes (`reference/intake.md`, two unconfirmed details);
  - the connector trial: a Confluence page write and read-back, the space id, and Slack to people as well as a channel;
  - CloudTrail lookups by resource name and by event source on a known change;
  - the ViewOnlyAccess grants, through `verify_access.py` (the simulated action names are unverified);
  - whether skill hooks fire inside subagents;
  - the calibration of the TypeSafe thresholds, which are uncalibrated starting values.
- **Commits whose co-author line names a different model than the session's.** The ledgers record the three foundation commits for tasks 4 to 6, whose message folded the body and a Haiku co-author line into the subject, and the guard round 4 commits `fe117c991d` and `7ad4b2a120`. Co-author lines elsewhere name the model that wrote each commit. None were rewritten, because rewriting history needs the owner's consent.
- **Rulings to confirm or reverse.** Every entry above was decided by the coordinating model. The ones with the largest cost if wrong are G9, G19 (more prompts), R8 and R14 (what a report may show), P5 (override by the engineer only), J11 (judging again after an edit) and RP5 (author text under its own heading).
