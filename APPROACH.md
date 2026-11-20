# Litmus "Tuesday Outage": Approach Summary

**Scope.** Variant v02. Baseline = Monday 14 Sep (111 jobs, 0 failures, 0 degraded, $0.633/job,
p95 4.0 min). Incident window = Tue 15 Sep 02:00 → Fri 00:00 (345 jobs: 190 failed). Kestrel docs are
treated as authoritative; a changelog entry counts only if Litmus's own traces show it acting.


## 1. Root causes

| Cause | Component | Onset (UTC) | Evidence span |
|---|---|---|---|
| OUTPUT_TOKEN_DEFAULT_LOWERED | synthesize | 2026-09-15T02:03:26Z | `sp_392fce096917` |
| REASONING_DEFAULT_CHANGED | synthesize | 2026-09-15T02:03:26Z | `sp_70539ee3fabb` |
| MODEL_ALIAS_DRIFT | orchestrator | 2026-09-15T03:33:58Z | `sp_cb49e55151f7` |
| CONNECTOR_FIELD_RENAMED | search | 2026-09-15T07:55:13Z | `sp_33ee6dcf2753` |
| RATE_TIER_DOWNGRADE | extract | 2026-09-15T07:55:15Z | `sp_39475ac6ea67` |

Onset = earliest span showing the cause acting; evidence = that span unless another cause uses it.

**OUTPUT_TOKEN_DEFAULT_LOWERED.** ov-02 left `synthesize.max_output_tokens` unset, so the Kestrel
default applies, and it fell from 16,000 to 4,000. 131 of 155 `write_review` calls after the window stop
at exactly 4,000 tokens (`finish_reason: length`); Monday had none, and its longest review was 7,808
tokens. The same 131 jobs logged `review_incomplete` errors.

**REASONING_DEFAULT_CHANGED.** Synthesize calls the alias with reasoning unset
[lead-ref: 2eb987689cc9d46c]; the alias default went from `off` to `medium`. Reasoning tokens: 0 on all
111 Monday calls, median 16,000 on all 155 after. Cost per call $0.144 → $0.348; duration 98 s → 138 s.
The onset call also shows truncation, so the evidence is a cleaner call (`sp_70539ee3fabb`, 16,000
reasoning tokens, `finish_reason: stop`). Orchestrator reasoning is set explicitly (2,000 tokens per plan
throughout), so it's unaffected.

**MODEL_ALIAS_DRIFT.** The orchestrator uses the alias (inferred from `model_requested`) and parses
tool-call arguments as `string`. The alias moved from `kp-2026-02` to `kp-2026-08`, which returns
arguments as objects (docs §1; vendor [lead-ref: f9fdd6c0ae20bdba]).
All 474 `tool_args_parse_error` errors ("expected JSON string … got object") are on `kp-2026-08`; none
of Monday's 111 plans on `kp-2026-02` failed. 158 plan sequences failed all three attempts, killing 104
jobs at their first plan and 54 at a re-plan.

**CONNECTOR_FIELD_RENAMED.** LitIndex v4 returns results in `items` (docs §9), but Search reads
`results` on structured queries.
All 101 structured v4 queries parsed 0 results from about 15 KB responses (Monday: 0 of 43 empty), and
every one fell back to `litindex-cache`. Those jobs had a median 6 papers in context against 11.5 for
others: thin reviews, which no alert catches. 07:55 is the first structured query after the window.

**RATE_TIER_DOWNGRADE.** The account moved from Tier 4 to Tier 2, and the allowance is shared across
the account [lead-ref: 98fa97a79aeb94ed]. The traces show the allowance fell, rather than load rising:
42 Litmus requests in the hour before the first 429, against 493 served cleanly in Monday's busiest
hour; the first rejection hit a lone wave of 6 fetches, while Monday passed 127 waves of 8; throttled
waves pass exactly 4. Result: 4,380 HTTP 429s (all `fetch_paper`), 175 stage re-dispatches, 32 failed
jobs. Component `extract`, where the rejections land.

## 2. Ruled out

| Code or claim | Evidence that cleared it |
|---|---|
| CACHE_TTL_DEFAULT_CHANGED | After the window Extract and Synthesize still read the cache after 5–60 idle minutes (120 and 103 jobs) and write only after 60+, so their TTLs are explicit ([lead-ref: 2eb987689cc9d46c]: 60 for Synthesize). Cite-check's is 10 in config. |
| CONCURRENCY_CAP_REDUCED | No `queue_timeout`, and `queue_wait_ms` is never set. The client limit (ov-04) already equals the new cap of 8. |
| TOOL_RESULT_LIMIT_LOWERED | 273 chunked fetches; no tool result cut to exactly 24,576 bytes; no decode errors. |
| TOOL_SCHEMA_STRICTNESS | Cite-check declares `additionalProperties: true`, which is exempt (docs §2). No schema rejections. |
| CONNECTOR_PAGINATION_CHANGED | Every `has_more` page was followed by a cursor fetch, and all 155 `verify_citations` calls checked every citation. |
| REGION_ENDPOINT_MIGRATION | Litmus is in us-east; the hostname change is eu-west only, on 1 Oct. |
| BATCH_API_DEPRECATION | Litmus makes only synchronous calls (runbook §1); there are no batch spans. |
| CREDENTIAL_MISUSE | `svc-litindex-reindex` is the agent team's quarterly re-index account [lead-ref: 6080527ba9c0626f]. Its traffic fits: one host, 01:00–02:58 on the third Wednesday of September, read-only, no model calls. |
| EMBEDDING_INDEX_STALE | A 41-day-old fallback is within a quarterly cycle. Thin reviews come from the fault-driven fallback, not from stale content. |
| CLOCK_SKEW | Spans are sorted, none ends before it starts, and none of 16,067 child spans falls outside its parent's interval. |
| d-0431 (logging, Tue 03:10) | Attribute keys identical before and after. Parse failures track the resolved model only, at a steady ~30% of plans per day; the one plan before 03:10 already used `kp-2026-08` and succeeded, as 70% do. Truncation began at 02:03, before d-0431. |
| Security: revoke and rotate | Rests on the refuted CREDENTIAL_MISUSE; security's spreadsheet omits agent-team accounts (agent owner; KCL-057). Revoking would break the re-index. |

## 3. Fix

| # | Operation | Why it's needed |
|---|---|---|
| 1 | `set_tool_arg_parsing` orchestrator → `object` | Fixes the 474 parse errors at the source. |
| 2 | `set_result_field` search → `items` | Fixes the 101 empty structured queries. v3 is sunset, so it can't be restored. |
| 3 | `set_max_output_tokens` synthesize → `16000` | Fixes the 131 truncated reviews. 16,000 is the old default and leaves headroom over Monday's 7,808. |
| 4 | `set_reasoning` synthesize → `off` | Restores Monday's behaviour (replay 3). |
| 5 | `set_retry_policy` orchestrator → `exp_backoff_jitter` | Respects the 4-second retry-after instead of burning the shared Tier 2 allowance (replay 2). |

| Replay | Fix set | Hard failures | Degraded outputs | Cost vs Monday | p95 job time |
|---|---|---|---|---|---|
| `dcae1ac633ac1ce9` | all 5 operations | 0 | 0 | 0.95× | 4.0 min |
| `5bba96f6df259946` | without op 5 | 86 | 0 | 1.25× | 5.8 min |
| `0f2a13470f865794` | without op 4 | 0 | 0 | 1.35× | 5.1 min |

**Why nothing smaller works.** Operations 4 and 5 were each dropped in a replay, and each drop broke at
least one metric. Operations 1–3 each fix a separate failure class seen directly in the traces, and none
fixes another's class. The only alternatives are equal-size substitutes: `pin_model` for op 1, and
`field: auto` for op 2.

**Not used.** `request_rate_tier`: excluded by FinOps (CFO approval, not this quarter) and unneeded,
since backoff alone fits Tier 2. `pin_model` orchestrator → `kp-2026-02`: same size as op 1 but
supported only until 31 Dec; op 1 is the durable fix. `set_retry_max`: unneeded (replay 1); under
immediate retries it only adds rejected load. `set_max_fanout` / `set_max_concurrency`: no queueing,
concurrency already at the cap of 8, and cutting fan-out risks the runbook's minimum Extract
parallelism of 6.

## 4. Causal graph (17 edges)

Direct edges only, each with a visible downstream effect; a script check confirms no shortcuts, cycles
or root-cause targets. Numbers are from §1 unless shown.

- MODEL_ALIAS_DRIFT → ARG_PARSE_ERRORS → JOB_FAILURES
- CONNECTOR_FIELD_RENAMED → EMPTY_PRIMARY_RESULTS → FALLBACK_INDEX_USED → THIN_REVIEWS
- OUTPUT_TOKEN_DEFAULT_LOWERED → OUTPUT_LENGTH_LIMIT_HIT → TRUNCATED_REVIEWS
- REASONING_DEFAULT_CHANGED → REASONING_TOKENS; REASONING_TOKENS → COST_SPIKE (1.35× in replay 3)
  and → LATENCY_INCREASE (5.1 min in replay 3)
- RATE_TIER_DOWNGRADE → RATE_LIMIT_REJECTIONS → IMMEDIATE_RETRY_STORM. Each 429 is retried four more
  times, 80 ms apart, despite a 4,000 ms retry-after.
- IMMEDIATE_RETRY_STORM → STAGE_REDISPATCH. 175 re-dispatches, all for `rate_limited`; with backoff
  they disappear (replay 1).
- STAGE_REDISPATCH → COST_SPIKE. Extract cost per job is $0.435 with a re-dispatch and $0.172
  without; rejected requests cost $0. 1.25× in replay 2.
- STAGE_REDISPATCH → LATENCY_INCREASE. The longest job is 8.1 min with a re-dispatch, 4.5 min
  without. 5.8 min in replay 2.
- STAGE_REDISPATCH → JOB_FAILURES. See the counterfactual below.
- JOB_FAILURES → ALERT_FLOOD. `JobErrorRate` fired in 4 periods covering most of Tue to Thu, at
  17–79%.

**Counterfactual for STAGE_REDISPATCH → JOB_FAILURES** (instead of RATE_LIMIT_REJECTIONS →
JOB_FAILURES). Replay 1 keeps Tier 2, so 429s still occur, yet it has 0 failures; replay 2 differs only
in using immediate retries and has 86. All 32 rate-limit failures used exactly 2 re-dispatches, the
runbook's maximum, before failing, and none failed without them. Jobs fail when the re-dispatch budget
runs out, not on a 429 itself.

**Left out.** RATE_LIMIT_REJECTIONS → STAGE_REDISPATCH (shortcut past the storm);
IMMEDIATE_RETRY_STORM → RATE_LIMIT_REJECTIONS (a cycle; retry rejections can't be separated from first
attempts); IMMEDIATE_RETRY_STORM → COST_SPIKE (429s cost $0); STAGE_REDISPATCH → ARG_PARSE_ERRORS
(exposure, not cause); rule-specific alerts → ALERT_FLOOD (not error-rate alerts); TRUNCATED_REVIEWS →
JOB_FAILURES (those jobs report success); JOB_FAILURES → COST_SPIKE (failed jobs are cheaper, which is
why FinOps saw cost per job fall, $0.633 → $0.528, while successful jobs cost about 1.4× more). Nodes fed
only by ruled-out causes are left out with them.

## 5. Tooling decisions

**Trace analysis.** Standard-library Python over `traces.jsonl`, split Monday / after the window,
grouped per job and per fetch wave to separate causes from amplifiers. The five unexported overlay
values were inferred from Monday's spans before any questions were spent.

**`solve.py`.** One detector per cause code: each confirms its cause (acting spans, visible-effect
edges, fix operations) or logs to stderr why it was ruled out. A confirmed cause always emits its fix
even if the config claims the setting is right, because the traces show what ran (KCL-058's SDK default
is that kind of hidden override); the config only picks parameters and enforces runbook constraints. No
span IDs or answers are hard-coded. Verified on v02 (matches replay 1, about 0.3 s) and on a synthetic
pack with decoys switched on, where the pagination, tool-result and concurrency detectors fire and emit
their fixes.

**Abandoned during the investigation**
- *Cache-write share as a TTL test.* Cite-check's share rose from 33/111 to 104/155, which looked like a
  TTL change; it was longer gaps between runs. Replaced by a per-job idle-gap test.
- *A global call-order gap test.* Sorting parallel calls put cache reads before the write that served
  them, producing impossible "reads after 96 idle minutes". Replaced by per-job grouping.
- *The first tool-result detector.* It flagged 30 raw LitIndex responses of 24.7–26 KB, which are the
  same sizes as Monday's and are parsed by Search, not delivered to a model. Replaced by the documented
  signature: an unchunked tool result cut to exactly 24,576 bytes.
- *Sliding windows (1 s to 1 h) to size the new allowance.* None fit, so the tier came from FinOps.

**Pitfall checked for and avoided.** `has_more and not cursor_followed` would count first pages, where
`cursor_followed` is `None`, as unfollowed: 131 false hits. The detector uses `is False` plus a
last-page check, which gives 0.

**Budget.** 4 of 13 questions, only on facts the traces couldn't settle (billing tier, argument
encoding, re-index account, Synthesize overlay), each checked against the traces. 3 of 5 replays: one to
prove sufficiency, two drop-one tests on the operations whose necessity was inferred; two held back.

## 6. Uncertainty

- **MODEL_ALIAS_DRIFT onset.** The first plan on `kp-2026-08` was at 02:02 (`sp_ccaf12a59e8d`) and was
  unharmed; the first failure was at 03:33. That's more than the one-hour tolerance apart. We used
  first harm, consistent with the other causes. Also unexplained: only about 30% of plans on `kp-2026-08`
  fail, and they are identical on every recorded attribute to those that succeed.
- **RATE_TIER_DOWNGRADE.** Tier changed at 02:00; first rejection 07:55. The allowance is account-wide
  and the amplifying retry policy is the orchestrator's; we chose `extract` and 07:55, where and when harm
  first appears.
- **Least certain edges.** IMMEDIATE_RETRY_STORM → STAGE_REDISPATCH (the alternative is a direct edge
  from RATE_LIMIT_REJECTIONS) and JOB_FAILURES → ALERT_FLOOD (depends on what the node's "error-rate
  alerts" means).
- **0.95× cost.** Not fully explained; plausibly job mix (Extract cost per successful job was already
  about 2.5% below Monday's).
- **Fallback index age.** Still 41 days after Wednesday's re-index, which the agent owner says refreshes
  it; 56 of 234 export requests were rejected. Either the refresh failed or the field lags. No harm to
  Litmus found, so no cause claimed.
- **Lead answers.** The vendor didn't explicitly rule out string-encoded arguments. Whether Synthesize
  needs reasoning for quality went unanswered; replay 1, with reasoning off, has 0 degraded outputs.
