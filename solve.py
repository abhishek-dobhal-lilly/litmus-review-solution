#!/usr/bin/env python3
"""Litmus "Tuesday Outage" investigator.

Usage: python3 solve.py <pack_dir>

Reads the incident pack and prints exactly one JSON object to stdout:
  {"root_causes": [...], "causal_graph": {"edges": [...]}, "fix_set": {"operations": [...]}}
All diagnostics go to stderr. Standard library only.

Design
------
* Effective config = base config (litmus_config.yaml) + overlay values from the deployment log
  + values that are still unknown inferred from Monday's traces.
* Fix rule: a cause confirmed from the traces always emits its fix operation, even if the config
  claims the setting is already right (the traces show what actually ran, e.g. KCL-058's SDK default
  overriding config). The config is used only to choose parameters and to respect constraints.
* One detector per cause code. Each detector either confirms its cause (with an onset span, the
  graph edges whose downstream effects are visible in the pack, and the fix operations it needs)
  or rules it out and logs why. Nothing is hard-coded per variant: no span IDs, no answers.
* Onset = earliest span showing the cause acting. Evidence = that span, unless another cause
  already uses it, in which case the cleanest distinct span showing the cause is used.
"""
import bisect
import json
import os
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime

# --- Facts taken from the shared (identical-across-variants) Kestrel docs and runbook -----------
RELEASE = "2026-09-15T02:00:00"      # Kestrel quarterly release window (brief, kestrel_docs)
BASELINE_END = "2026-09-15T00:00:00"  # Monday = normal baseline day
ALIAS_PREFIX = "kp-"                  # snapshots are kp-YYYY-MM; anything else is an alias
RETIRED_SNAPSHOTS = {"kp-2025-11"}    # kestrel_docs: retired at the release window
TOOL_RESULT_CAP = 24 * 1024           # kestrel_docs §6: new cap, truncates at the cap
OLD_OUTPUT_DEFAULT = 16000            # kestrel_docs: previous default max_output_tokens
NEW_TTL_DEFAULT_MIN = 5               # kestrel_docs §3: new default cache TTL
OLD_TTL_DEFAULT_MIN = 60
CITE_TTL_MAX = 10                     # runbook §5: Cite-check cache must stay <= 10 minutes
MIN_EXTRACT_PARALLELISM = 6           # runbook §5: below 6 breaches the SLA
NEW_CONCURRENCY_CAP = 8               # kestrel_docs §8
INDEX_STALE_DAYS = 92                 # runbook: litindex-cache is refreshed quarterly
DEFAULT_FIELD_BY_VERSION = {"v3": "results", "v4": "items"}  # kestrel_docs §9 (re-parsed below)


def log(*a):
    print(*a, file=sys.stderr)


def ts(x):
    return datetime.fromisoformat(x.replace("Z", "+00:00")).timestamp()


def iso(span):
    return span["start"][:19] + "Z"


def attrs(s):
    return s.get("attrs") or {}


def is_alias(model):
    return bool(model) and not str(model).startswith(ALIAS_PREFIX)


def median(v, default=0):
    v = [x for x in v if x is not None]
    return statistics.median(v) if v else default


# --- Pack loading --------------------------------------------------------------------------------
def find(pack, name):
    for root, _dirs, files in os.walk(pack):
        if name in files:
            return os.path.join(root, name)
    return None


def read(pack, name):
    p = find(pack, name)
    if not p:
        log(f"[warn] {name} not found in pack")
        return ""
    with open(p, encoding="utf-8") as f:
        return f.read()


def scalar(v):
    v = v.strip().strip('"').strip("'")
    low = v.lower()
    if low in ("null", "~", ""):
        return None
    if low == "true":
        return True
    if low == "false":
        return False
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    return v


OVERLAY = "__overlay__"


def parse_config(text):
    """Two-level YAML as used by litmus_config.yaml (section: / key: value)."""
    cfg, section = {}, None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        key, _, val = line.strip().partition(":")
        if indent == 0 and val.strip() == "":
            section = key
            cfg.setdefault(section, {})
            continue
        v = scalar(val)
        if v == "overlay":
            v = OVERLAY
        if indent == 0:
            cfg[key] = v
            section = None
        else:
            cfg.setdefault(section, {})[key] = v
    return cfg


def parse_overlays(text):
    """Overlay rows of the deployment log: `section.key` -> `value` / unset."""
    out = {}
    for line in text.splitlines():
        m = re.search(r"`([\w]+)\.([\w.]+)`\s*(?:→|->)\s*(?:`([^`]*)`|(unset))", line)
        if m:
            sec, key, val, unset = m.groups()
            out[(sec, key)] = None if unset else scalar(val)
    return out


def parse_field_map(docs):
    m = re.search(r"LitIndex\s*\|\s*(v\d+)\s*\|[^\n]*?field\s*\*\*`(\w+)`\*\*[^\n]*?\((v\d+) used `(\w+)`\)", docs)
    if m:
        return {m.group(1): m.group(2), m.group(3): m.group(4)}
    return dict(DEFAULT_FIELD_BY_VERSION)


# --- Context ---------------------------------------------------------------------------------------
class Ctx:
    def __init__(self, pack):
        self.pack = pack
        path = find(pack, "traces.jsonl")
        with open(path, encoding="utf-8") as f:
            self.spans = [json.loads(l) for l in f if l.strip()]
        self.idx = {s["span_id"]: s for s in self.spans}
        self.by_trace = defaultdict(list)
        for s in self.spans:
            self.by_trace[s["trace_id"]].append(s)
        for v in self.by_trace.values():
            v.sort(key=lambda s: s["start"])
        self.base = [s for s in self.spans if s["start"] < BASELINE_END]
        self.post = [s for s in self.spans if s["start"] >= RELEASE]
        self.litmus_post = [s for s in self.post if s["component"] != "external"]
        self.cfg = parse_config(read(pack, "litmus_config.yaml"))
        self.overlays = parse_overlays(read(pack, "deployment_log.md"))
        self.docs = read(pack, "kestrel_docs.md")
        self.alerts = read(pack, "alert_history.csv")
        self.field_map = parse_field_map(self.docs)
        self.eff = self.effective_config()
        self.failures = self.classify_failures()

    # effective config ------------------------------------------------------------------------
    def effective_config(self):
        eff = {}
        for sec, kv in self.cfg.items():
            if isinstance(kv, dict):
                for k, v in kv.items():
                    eff[(sec, k)] = v
            else:
                eff[(sec, None)] = kv
        for k, v in self.overlays.items():
            eff[k] = v
        # infer remaining unknown overlay values from Monday's traces
        for (sec, key), v in list(eff.items()):
            if v != OVERLAY:
                continue
            calls = [s for s in self.base if s["kind"] == "llm_call" and s["component"] == sec]
            if key == "model" and calls:
                eff[(sec, key)] = Counter(s.get("model_requested") for s in calls).most_common(1)[0][0]
            elif key == "reasoning" and calls:
                eff[(sec, key)] = "explicit" if any(s["tokens"]["reasoning"] > 0 for s in calls) else "unset_or_off"
            elif key == "cache_ttl_minutes":
                eff[(sec, key)] = "inferred:" + str(self.infer_ttl(sec))
            else:
                eff[(sec, key)] = "unknown"
        for k in sorted(eff, key=str):
            log(f"[config] {k[0]}.{k[1]} = {eff[k]!r}")
        return eff

    def get(self, sec, key, default=None):
        return self.eff.get((sec, key), default)

    # cache gap analysis ------------------------------------------------------------------------
    def cache_jobs(self, comp, spans):
        """Per job: (start of first cached call, idle gap in minutes since previous job's last
        cached call ended, wrote_cache) for the component's cached model calls."""
        calls = [s for s in spans if s["kind"] == "llm_call" and s["component"] == comp
                 and (s["tokens"].get("cache_read", 0) or s["tokens"].get("cache_write", 0))]
        jobs = defaultdict(list)
        for s in calls:
            jobs[s["trace_id"]].append(s)
        ordered = sorted(jobs.values(), key=lambda L: min(x["start"] for x in L))
        out, prev_end = [], None
        for L in ordered:
            st = min(ts(x["start"]) for x in L)
            en = max(ts(x["end"]) for x in L)
            wrote = any(x["tokens"].get("cache_write", 0) for x in L)
            gap = None if prev_end is None else (st - prev_end) / 60
            out.append((L, gap, wrote))
            prev_end = en if prev_end is None else max(prev_end, en)
        return out

    def infer_ttl(self, comp):
        rows = [r for r in self.cache_jobs(comp, self.spans) if r[1] is not None]
        reads = [g for L, g, w in rows if not w]
        if not reads:
            return "undetermined"
        post_reads = [g for L, g, w in rows if not w and L[0]["start"] >= RELEASE]
        if post_reads and max(post_reads) > NEW_TTL_DEFAULT_MIN:
            return f"explicit>= {max(post_reads):.0f}min"
        return "default"

    # job failure classification -----------------------------------------------------------------
    def classify_failures(self):
        out = []
        for j in self.post:
            if j["kind"] != "job" or j["status"] != "error":
                continue
            L = self.by_trace[j["trace_id"]]
            errs = [x for x in L if x["status"] == "error" and x["kind"] != "job"]
            last = errs[-1].get("error_type") if errs else None
            nred = sum(1 for x in L if x["name"].startswith("redispatch"))
            out.append({"job": j, "last_error": last, "redispatches": nred})
        log(f"[jobs] post-window failures by (last error, redispatches): "
            f"{dict(Counter((x['last_error'], x['redispatches']) for x in out))}")
        return out


# --- Finding container -----------------------------------------------------------------------------
class Finding:
    def __init__(self, code, component, acting, clean=None):
        self.code = code
        self.component = component
        self.acting = acting            # spans showing the cause acting, in time order
        self.clean = clean or []        # preferred alternatives if the onset span is shared
        self.edges = []                 # (A, B, evidence)
        self.ops = []
        self.evidence = None

    @property
    def onset(self):
        return self.acting[0]

    def edge(self, a, b, why):
        self.edges.append((a, b, why))

    def op(self, **kw):
        self.ops.append(kw)


RULED_OUT = []


def rule_out(code, why):
    RULED_OUT.append((code, why))
    log(f"[ruled out] {code}: {why}")


# --- Detectors -------------------------------------------------------------------------------------
def det_model_alias_drift(c):
    code = "MODEL_ALIAS_DRIFT"
    llm_b = [s for s in c.base if s["kind"] == "llm_call" and is_alias(s.get("model_requested"))]
    llm_p = [s for s in c.post if s["kind"] == "llm_call" and is_alias(s.get("model_requested"))]
    base_res = defaultdict(set)
    for s in llm_b:
        base_res[s["component"]].add(s.get("model_resolved"))
    drifted = {s["component"] for s in llm_p if s.get("model_resolved") not in base_res[s["component"]]}
    if not drifted:
        return rule_out(code, "no alias-addressed component resolved to a new snapshot")
    base_err = [s for s in llm_b if s["component"] in drifted and s["status"] == "error"]
    errs = [s for s in llm_p if s["component"] in drifted and s["status"] == "error"
            and s.get("model_resolved") not in base_res[s["component"]]]
    if not errs or len(base_err) > 0.2 * len(errs):
        return rule_out(code, f"alias moved for {sorted(drifted)} but no new errors on the new snapshot")
    f = Finding(code, errs[0]["component"], errs)
    parse = [s for s in errs if "parse" in (s.get("error_type") or "")]
    if parse:
        f.edge(code, "ARG_PARSE_ERRORS", f"{len(parse)} {parse[0].get('error_type')} on "
               f"{parse[0].get('model_resolved')}, 0 on Monday's snapshot")
        n = sum(1 for x in c.failures if "parse" in (x["last_error"] or ""))
        if n:
            f.edge("ARG_PARSE_ERRORS", "JOB_FAILURES", f"{n} jobs ended on plan parse failures")
        msg = (parse[0].get("error_message") or "").lower()
        if f.component == "orchestrator":
            mode = "object" if "got object" in msg else "string" if "got string" in msg else None
            if mode:
                f.op(op="set_tool_arg_parsing", component="orchestrator", mode=mode,
                     note=f"new snapshot returns tool-call arguments as {mode}s ({len(parse)} parse errors)")
    if not f.ops and f.component in ("orchestrator", "synthesize"):
        snap = Counter(s.get("model_resolved") for s in llm_b if s["component"] == f.component).most_common(1)
        if snap and snap[0][0] not in RETIRED_SNAPSHOTS:
            f.op(op="pin_model", component=f.component, snapshot=snap[0][0],
                 note="pin to the snapshot that ran cleanly on Monday")
    return f


def det_connector_field_renamed(c):
    code = "CONNECTOR_FIELD_RENAMED"
    q_b = [s for s in c.base if s["name"] == "litindex.query" and attrs(s).get("query_mode") == "structured"]
    q_p = [s for s in c.post if s["name"] == "litindex.query" and attrs(s).get("query_mode") == "structured"]
    if not q_p:
        return rule_out(code, "no structured LitIndex queries after the window")

    def wrong(s):
        a = attrs(s)
        exp = c.field_map.get(a.get("connector_version"))
        return a.get("result_count") == 0 and a.get("result_field_read") not in (exp, "auto", "helper", None)

    bad = [s for s in q_p if wrong(s)]
    base_zero = sum(1 for s in q_b if attrs(s).get("result_count") == 0)
    if len(bad) < 3 or len(bad) < 0.5 * len(q_p) or (q_b and base_zero > 0.2 * len(q_b)):
        return rule_out(code, f"{len(bad)}/{len(q_p)} structured queries read a wrong field")
    f = Finding(code, "search", bad)
    ver = attrs(bad[0]).get("connector_version")
    f.edge(code, "EMPTY_PRIMARY_RESULTS", f"{len(bad)}/{len(q_p)} structured {ver} queries read "
           f"'{attrs(bad[0]).get('result_field_read')}' and parsed 0 results (Monday: {base_zero}/{len(q_b)})")
    fb_traces = {s["trace_id"] for s in bad
                 if any(x["name"] == "litindex_cache.query" and x["start"] >= s["start"] for x in c.by_trace[s["trace_id"]])}
    if fb_traces:
        f.edge("EMPTY_PRIMARY_RESULTS", "FALLBACK_INDEX_USED", f"{len(fb_traces)} jobs fell back to litindex-cache")

        def pic(trs):
            return [attrs(x).get("papers_in_context") for t in trs for x in c.by_trace[t] if x["name"] == "write_review"]
        ok_traces = {j["trace_id"] for j in c.post if j["kind"] == "job"} - fb_traces
        thin, normal = median(pic(fb_traces), None), median(pic(ok_traces), None)
        if thin is not None and normal and thin < 0.75 * normal:
            f.edge("FALLBACK_INDEX_USED", "THIN_REVIEWS", f"median papers in context {thin} vs {normal}")
    field = c.field_map.get(ver, "auto")
    if f.acting:  # confirmed in traces -> always fix; config only picks the field
        f.op(op="set_result_field", component="search", field=field,
             note=f"LitIndex {ver} returns results in '{field}'")
    return f


def det_output_token_default_lowered(c):
    code = "OUTPUT_TOKEN_DEFAULT_LOWERED"
    t_b = [s for s in c.base if s["kind"] == "llm_call" and s.get("finish_reason") == "length"]
    t_p = [s for s in c.post if s["kind"] == "llm_call" and s.get("finish_reason") == "length"]
    if len(t_p) < 3 or t_b:
        return rule_out(code, f"{len(t_p)} length-capped calls after the window, {len(t_b)} on Monday")
    comp = Counter(s["component"] for s in t_p).most_common(1)[0][0]
    if c.get(comp, "max_output_tokens") not in (None, OVERLAY, "unknown"):
        return rule_out(code, f"{comp} sets its own max_output_tokens")
    acting = [s for s in t_p if s["component"] == comp]
    f = Finding(code, comp, acting)
    cap = Counter(s["tokens"]["output"] for s in acting).most_common(1)[0][0]
    f.edge(code, "OUTPUT_LENGTH_LIMIT_HIT", f"{len(acting)} {comp} calls stop at {cap} tokens (finish=length)")
    incomplete = [s for s in c.post if s.get("error_type") == "review_incomplete"]
    if comp == "synthesize" and (incomplete or acting):
        f.edge("OUTPUT_LENGTH_LIMIT_HIT", "TRUNCATED_REVIEWS", f"{len(incomplete)} review_incomplete errors")
    if comp == "synthesize":
        base_max = max([s["tokens"]["output"] for s in c.base if s["component"] == comp and s["kind"] == "llm_call"] or [0])
        n = OLD_OUTPUT_DEFAULT if base_max * 1.5 <= OLD_OUTPUT_DEFAULT else 32000
        f.op(op="set_max_output_tokens", component="synthesize", n=n,
             note=f"restore previous default; Monday max output {base_max}")
    return f


def det_reasoning_default_changed(c):
    code = "REASONING_DEFAULT_CHANGED"
    found = None
    for comp in ("orchestrator", "search", "extract", "synthesize", "cite_check"):
        b = [s for s in c.base if s["kind"] == "llm_call" and s["component"] == comp and is_alias(s.get("model_requested"))]
        p = [s for s in c.post if s["kind"] == "llm_call" and s["component"] == comp and is_alias(s.get("model_requested"))]
        if len(b) < 5 or not p or any(s["tokens"]["reasoning"] > 0 for s in b):
            continue
        r = [s for s in p if s["tokens"]["reasoning"] > 0]
        if len(r) < 0.5 * len(p):
            continue
        clean = [s for s in r if s.get("finish_reason") in ("stop", "tool_use") and s["status"] == "ok"]
        f = Finding(code, comp, r, clean)
        f.edge(code, "REASONING_TOKENS", f"{comp}: reasoning 0 on Monday, median {median([s['tokens']['reasoning'] for s in r])} after")
        cost_b, cost_p = median([s.get("cost_usd") for s in b]), median([s.get("cost_usd") for s in p])
        if cost_b and cost_p > 1.2 * cost_b:
            f.edge("REASONING_TOKENS", "COST_SPIKE", f"{comp} cost/call ${cost_b:.3f} -> ${cost_p:.3f}")
        dur_b, dur_p = median([s["duration_ms"] for s in b]), median([s["duration_ms"] for s in p])
        if dur_b and dur_p > 1.15 * dur_b:
            f.edge("REASONING_TOKENS", "LATENCY_INCREASE", f"{comp} call duration {dur_b/1000:.0f}s -> {dur_p/1000:.0f}s")
        # runbook: orchestrator reasoning must stay medium; elsewhere restore Monday's 'off'
        f.op(op="set_reasoning", component=comp, mode="medium" if comp == "orchestrator" else "off",
             note="reasoning was unset and picked up the new alias default; Monday ran with none")
        if found is None or r[0]["start"] < found.onset["start"]:
            found = f
    if not found:
        return rule_out(code, "no alias component gained reasoning tokens it lacked on Monday")
    return found


def det_rate_tier_downgrade(c):
    code = "RATE_TIER_DOWNGRADE"
    r_b = [s for s in c.base if s.get("error_type") == "rate_limited"]
    r_p = [s for s in c.litmus_post if s.get("error_type") == "rate_limited"]
    if not r_p or r_b:
        return rule_out(code, f"{len(r_p)} rate_limited after the window, {len(r_b)} on Monday")
    req = lambda s: s["component"] != "external" and s["kind"] in ("llm_call", "tool_call", "connector_request")
    base_t = sorted(ts(s["start"]) for s in c.base if req(s))
    peak = 0
    for i, t in enumerate(base_t):
        peak = max(peak, i - bisect.bisect_left(base_t, t - 3600) + 1)
    t1 = ts(r_p[0]["start"])
    before = sum(1 for s in c.spans if req(s) and t1 - 3600 <= ts(s["start"]) < t1)
    log(f"[rate] requests in hour before first 429: {before}; Monday busiest served hour: {peak}")
    if before >= 0.5 * peak:
        return rule_out(code, "first 429s came at load comparable to Monday's peak (load, not allowance)")
    f = Finding(code, r_p[0]["component"], r_p)
    f.edge(code, "RATE_LIMIT_REJECTIONS", f"{len(r_p)} HTTP 429; first at {before} req/h vs Monday peak {peak} req/h with none")
    immediate = [s for s in r_p if attrs(s).get("retry_policy") == "immediate"]
    storm = bool(immediate)
    if storm:
        f.edge("RATE_LIMIT_REJECTIONS", "IMMEDIATE_RETRY_STORM",
               f"{len(immediate)} rejections retried immediately despite retry_after_ms={attrs(immediate[0]).get('retry_after_ms')}")
    red = [s for s in c.litmus_post if s["name"].startswith("redispatch") and attrs(s).get("reason") == "rate_limited"]
    if red:
        f.edge("IMMEDIATE_RETRY_STORM" if storm else "RATE_LIMIT_REJECTIONS", "STAGE_REDISPATCH",
               f"{len(red)} stage re-dispatches with reason rate_limited")
        rf = [x for x in c.failures if x["last_error"] == "rate_limited"]
        if rf and all(x["redispatches"] > 0 for x in rf):
            f.edge("STAGE_REDISPATCH", "JOB_FAILURES",
                   f"{len(rf)} jobs failed rate-limited only after exhausting re-dispatch (max {max(x['redispatches'] for x in rf)})")
        jobs = [j for j in c.post if j["kind"] == "job"]
        has_red = lambda j: any(x["name"].startswith("redispatch") for x in c.by_trace[j["trace_id"]])
        ext_cost = lambda j: sum(x.get("cost_usd", 0) for x in c.by_trace[j["trace_id"]] if x["component"] == "extract")
        with_r = [ext_cost(j) for j in jobs if has_red(j)]
        without = [ext_cost(j) for j in jobs if not has_red(j)]
        if with_r and without and statistics.mean(with_r) > 1.5 * statistics.mean(without):
            f.edge("STAGE_REDISPATCH", "COST_SPIKE",
                   f"Extract cost/job ${statistics.mean(with_r):.3f} with re-dispatch vs ${statistics.mean(without):.3f} without")
        d_with = [j["duration_ms"] for j in jobs if has_red(j)]
        d_without = [j["duration_ms"] for j in jobs if not has_red(j)]
        if d_with and d_without and max(d_with) > 1.25 * max(d_without):
            f.edge("STAGE_REDISPATCH", "LATENCY_INCREASE",
                   f"longest job {max(d_with)/60000:.1f} min with re-dispatch vs {max(d_without)/60000:.1f} min without")
    # A tier upgrade is excluded (FinOps: needs CFO approval, not this quarter); fix the retry storm.
    if f.acting:  # confirmed in traces -> always fix; config only picks parameters
        f.op(op="set_retry_policy", component="orchestrator", policy="exp_backoff_jitter",
             note="honour retry-after under the lower tier instead of burning the shared allowance")
    return f


def det_cache_ttl_default_changed(c):
    code = "CACHE_TTL_DEFAULT_CHANGED"
    for comp in ("extract", "synthesize", "cite_check"):
        conf = c.get(comp, "cache_ttl_minutes")
        if isinstance(conf, int):
            log(f"[cache] {comp}: explicit TTL {conf} min in config -> unaffected by default change")
            continue
        rows = [r for r in c.cache_jobs(comp, c.spans) if r[1] is not None]
        post = [r for r in rows if r[0][0]["start"] >= RELEASE]
        mid_reads = [g for L, g, w in post if not w and g > NEW_TTL_DEFAULT_MIN]
        mid_writes = [(L, g) for L, g, w in post if w and NEW_TTL_DEFAULT_MIN < g < OLD_TTL_DEFAULT_MIN]
        log(f"[cache] {comp}: post reads after >{NEW_TTL_DEFAULT_MIN}min idle={len(mid_reads)}, "
            f"writes after {NEW_TTL_DEFAULT_MIN}-{OLD_TTL_DEFAULT_MIN}min idle={len(mid_writes)}")
        if len(mid_writes) >= 3 and len(mid_reads) < 0.1 * len(mid_writes):
            acting = [next(x for x in L if x["tokens"].get("cache_write", 0)) for L, g in mid_writes]
            f = Finding(code, comp, acting)
            f.edge(code, "CACHE_MISSES", f"{comp}: {len(mid_writes)} cache writes after idle gaps under 60 min")
            f.edge("CACHE_MISSES", "COST_SPIKE", "cache writes billed instead of reads")
            f.op(op="set_cache_ttl", component=comp, minutes=CITE_TTL_MAX if comp == "cite_check" else OLD_TTL_DEFAULT_MIN,
                 note="restore Monday's effective TTL")
            return f
    return rule_out(code, "every cached component reads after idle gaps >5 min (explicit TTL) or sets TTL in config")


def det_concurrency_cap_reduced(c):
    code = "CONCURRENCY_CAP_REDUCED"
    q = [s for s in c.litmus_post if s.get("error_type") == "queue_timeout" or (attrs(s).get("queue_wait_ms") or 0) > 0]
    if not q:
        return rule_out(code, "no queue_timeout and no queue_wait_ms on any call")
    f = Finding(code, q[0]["component"], q)
    to = [s for s in q if s.get("error_type") == "queue_timeout"]
    if to:
        f.edge(code, "QUEUE_TIMEOUTS", f"{len(to)} HTTP 504 queue_timeout")
        if any(x["last_error"] == "queue_timeout" for x in c.failures):
            f.edge("QUEUE_TIMEOUTS", "JOB_FAILURES", "jobs ended on queue timeouts")
    cur = c.get("orchestrator", "max_concurrency")
    n = cur if isinstance(cur, int) and MIN_EXTRACT_PARALLELISM <= cur <= NEW_CONCURRENCY_CAP else NEW_CONCURRENCY_CAP
    if f.acting:  # confirmed in traces -> always fix; config only picks parameters
        f.op(op="set_max_concurrency", component="orchestrator", n=n,
             note="stay within the new per-key in-flight cap")
    return f


def det_tool_result_limit_lowered(c):
    code = "TOOL_RESULT_LIMIT_LOWERED"
    # Truncation signature (kestrel_docs §6): a tool result delivered to a model, unchunked, cut to
    # exactly the cap. Raw connector responses parsed by Search itself (e.g. 24.7-26 KB LitIndex
    # payloads, same sizes on Monday) arrive whole and are not subject to the cap.
    trunc = [s for s in c.litmus_post if s["kind"] == "tool_call"
             and attrs(s).get("bytes_received") == TOOL_RESULT_CAP and not attrs(s).get("chunk")]
    dec = [s for s in c.litmus_post if s.get("error_type") == "json_decode_error"]
    acting = sorted(trunc + dec, key=lambda s: s["start"])
    if not acting:
        chunked = sum(1 for s in c.litmus_post if attrs(s).get("chunk"))
        return rule_out(code, f"no unchunked tool result cut to exactly {TOOL_RESULT_CAP} bytes, no decode errors ({chunked} chunked fetches)")
    f = Finding(code, acting[0]["component"], acting)
    f.edge(code, "TRUNCATED_TOOL_RESULT", f"{len(trunc)} results at the 24 KB cap, {len(dec)} decode errors")
    if acting[0]["component"] == "extract":
        f.edge("TRUNCATED_TOOL_RESULT", "PARTIAL_EXTRACTION", "Extract received only the first 24 KB")
        if f.acting:  # confirmed in traces -> always fix; config only picks parameters
            f.op(op="set_result_chunking", component="extract", enabled=True, note="deliver large papers in chunks")
    return f


def det_tool_schema_strictness(c):
    code = "TOOL_SCHEMA_STRICTNESS"
    rej = [s for s in c.litmus_post if s.get("error_type") == "tool_schema_validation_error"]
    if not rej:
        return rule_out(code, "no tool_schema_validation_error (Cite-check declares additionalProperties: "
                        f"{c.get('cite_check', 'tool_schema.additional_properties')})")
    f = Finding(code, rej[0]["component"], rej)
    f.edge(code, "SCHEMA_REJECTIONS", f"{len(rej)} schema rejections")
    if f.acting:  # confirmed in traces -> always fix; config only picks parameters
        f.op(op="update_tool_schema", component="cite_check", additional_properties=True,
             note="schemas declaring additionalProperties: true are unaffected")
    return f


def det_connector_pagination_changed(c):
    code = "CONNECTOR_PAGINATION_CHANGED"
    lk = [s for s in c.litmus_post if s["name"] == "citeregistry.lookup"]
    unfollowed = [s for s in lk if attrs(s).get("has_more") and attrs(s).get("cursor_followed") is False]
    # last-page check: a lookup with has_more must be followed by another page in the same job
    dropped = []
    for s in lk:
        if attrs(s).get("has_more"):
            later = [x for x in c.by_trace[s["trace_id"]] if x["name"] == "citeregistry.lookup" and x["start"] > s["start"]]
            if not later and attrs(s).get("cursor_followed") is not True:
                dropped.append(s)
    under = [s for s in c.litmus_post if s["name"] == "verify_citations" and attrs(s).get("verdict") == "verified"
             and (attrs(s).get("citations_checked") or 0) < (attrs(s).get("citations_total") or 0)]
    acting = sorted({s["span_id"]: s for s in unfollowed + dropped}.values(), key=lambda s: s["start"])
    if not acting:
        return rule_out(code, f"every has_more page was followed; {len(under)} under-verified reviews")
    f = Finding(code, "cite_check", acting)
    f.edge(code, "PARTIAL_CITATION_SET", f"{len(acting)} lookups stopped at a page with has_more")
    if under:
        f.edge("PARTIAL_CITATION_SET", "UNDER_VERIFIED_CITATIONS", f"{len(under)} reviews verified with unchecked citations")
    if f.acting:  # confirmed in traces -> always fix; config only picks parameters
        f.op(op="set_follow_cursor", component="cite_check", enabled=True, note="fetch all pages")
    return f


def det_region_endpoint_migration(c):
    code = "REGION_ENDPOINT_MIGRATION"
    region = c.get("region", None)
    errs = [s for s in c.litmus_post if re.search(r"endpoint|dns|host|connect", s.get("error_type") or "")]
    if region != "eu-west" or not errs:
        return rule_out(code, f"region {region}; {len(errs)} endpoint errors (hostname change is eu-west, 1 Oct)")
    f = Finding(code, errs[0]["component"], errs)
    f.op(op="set_region", region="us-east", note="us-east endpoint unchanged")
    return f


def det_batch_api_deprecation(c):
    code = "BATCH_API_DEPRECATION"
    b = [s for s in c.litmus_post if "batch" in s["name"].lower() and s["status"] == "error"]
    if not b:
        return rule_out(code, "Litmus makes no Batch API calls (synchronous only)")
    return Finding(code, b[0]["component"], b)


def det_credential_misuse(c):
    code = "CREDENTIAL_MISUSE"
    ext = [s for s in c.spans if s["component"] == "external"]
    if not ext:
        return rule_out(code, "no external traffic")
    bad = []
    for acct, L in defaultdict(list, {a: [s for s in ext if attrs(s).get("service_account") == a]
                                       for a in {attrs(s).get("service_account") for s in ext}}).items():
        ips = {attrs(s).get("client_ip") for s in L}
        span_h = (max(ts(s["end"]) for s in L) - min(ts(s["start"]) for s in L)) / 3600
        read_only = all(s["kind"] != "llm_call" and re.search(r"export|query|read", s["name"]) for s in L)
        maint = bool(acct) and re.search(r"reindex|re-index|maint", acct) and read_only and len(ips) == 1 and span_h <= 3
        log(f"[security] account {acct}: {len(L)} requests, ips={sorted(map(str, ips))}, {span_h:.1f} h, "
            f"read_only={read_only} -> {'documented maintenance job' if maint else 'unexplained'}")
        if not maint:
            bad += L
    if not bad:
        return rule_out(code, "all external traffic matches the documented quarterly re-index job (runbook §8)")
    bad.sort(key=lambda s: s["start"])
    f = Finding(code, "search", bad)
    f.edge(code, "UNAUTHORISED_TRAFFIC", f"{len(bad)} requests from unexplained accounts")
    for acct in sorted({attrs(s).get("service_account") for s in bad if attrs(s).get("service_account")}):
        f.op(op="revoke_service_account", name=acct, note="traffic not explained by any documented job")
    return f


def det_embedding_index_stale(c):
    code = "EMBEDDING_INDEX_STALE"
    fb = [s for s in c.litmus_post if s["name"] == "litindex_cache.query"]
    ages = [attrs(s).get("index_snapshot_age_days") for s in fb if attrs(s).get("index_snapshot_age_days") is not None]
    if not ages or max(ages) <= INDEX_STALE_DAYS:
        if ages and len(set(ages)) == 1 and any(s["component"] == "external" for s in c.spans):
            log(f"[index] note: fallback age constant at {ages[0]} days despite a maintenance run")
        return rule_out(code, f"fallback index age {max(ages) if ages else 'n/a'} days <= quarterly refresh")
    stale = [s for s in fb if attrs(s).get("index_snapshot_age_days", 0) > INDEX_STALE_DAYS]
    f = Finding(code, "search", stale)
    f.edge(code, "STALE_INDEX_CONTENT", f"fallback data {max(ages)} days old")
    return f


def det_clock_skew(c):
    code = "CLOCK_SKEW"
    bad = [s for s in c.spans if s["end"] < s["start"]]
    for s in c.spans:
        p = c.idx.get(s.get("parent_id"))
        if p and (s["start"] < p["start"] or s["end"] > p["end"]):
            bad.append(s)
    with_parent = sum(1 for s in c.spans if s.get("parent_id"))
    if len(bad) <= 0.01 * max(with_parent, 1):
        return rule_out(code, f"{len(bad)} of {with_parent} child spans outside their parent interval")
    bad.sort(key=lambda s: s["start"])
    f = Finding(code, bad[0]["component"], bad)
    f.edge(code, "TIMESTAMP_DISORDER", f"{len(bad)} spans out of order")
    return f


DETECTORS = [det_model_alias_drift, det_connector_field_renamed, det_output_token_default_lowered,
             det_reasoning_default_changed, det_rate_tier_downgrade, det_cache_ttl_default_changed,
             det_concurrency_cap_reduced, det_tool_result_limit_lowered, det_tool_schema_strictness,
             det_connector_pagination_changed, det_region_endpoint_migration, det_batch_api_deprecation,
             det_credential_misuse, det_embedding_index_stale, det_clock_skew]


# --- Assembly --------------------------------------------------------------------------------------
def assign_evidence(findings):
    """Evidence = onset span, unless shared; then the cause with a cleaner alternative moves."""
    used = {}
    for f in sorted(findings, key=lambda f: (f.onset["start"], -len(f.clean))):
        f.evidence = f.onset
        if f.onset["span_id"] in used:
            other = used[f.onset["span_id"]]
            mover = f if len(f.clean) >= len(other.clean) else other
            alt = [s for s in (mover.clean or mover.acting) if s["span_id"] not in used and s["span_id"] != f.onset["span_id"]]
            if alt:
                mover.evidence = alt[0]
                log(f"[evidence] {mover.code}: onset span shared with "
                    f"{(other if mover is f else f).code}; using distinct span {alt[0]['span_id']}")
                if mover is other:
                    used[alt[0]["span_id"]] = other
        used[f.evidence["span_id"]] = f


def alert_flood_edge(c):
    rows = [l for l in c.alerts.splitlines() if ",JobErrorRate," in l]
    post = [l for l in rows if (re.search(r"\d{4}-\d\d-\d\dT[\d:.]+Z?", l) or [""])[0] >= RELEASE[:16]]
    return len(post) >= 2, len(post)


def main():
    if len(sys.argv) < 2:
        log("usage: python3 solve.py <pack_dir>")
        sys.exit(2)
    c = Ctx(os.path.abspath(sys.argv[1]))
    findings = []
    for det in DETECTORS:
        try:
            f = det(c)
            if f:
                findings.append(f)
                log(f"[confirmed] {f.code} ({f.component}) onset {iso(f.onset)} span {f.onset['span_id']}")
        except Exception as e:  # never let one detector break the submission
            log(f"[error] {det.__name__}: {e!r}")
    assign_evidence(findings)

    edges, seen = [], set()
    for f in sorted(findings, key=lambda f: f.onset["start"]):
        for a, b, why in f.edges:
            if (a, b) not in seen:
                seen.add((a, b))
                edges.append([a, b])
                log(f"[edge] {a} -> {b}: {why}")
    targets = {b for _a, b in seen}
    flood, n = alert_flood_edge(c)
    if "JOB_FAILURES" in targets and flood:
        edges.append(["JOB_FAILURES", "ALERT_FLOOD"])
        log(f"[edge] JOB_FAILURES -> ALERT_FLOOD: JobErrorRate fired in {n} periods after the window")

    ops, seen_ops = [], set()
    for f in sorted(findings, key=lambda f: f.onset["start"]):
        for o in f.ops:
            key = (o["op"], o.get("component"))
            if key not in seen_ops:
                seen_ops.add(key)
                ops.append(o)

    out = {
        "root_causes": [{"cause_code": f.code, "component": f.component, "onset_time": iso(f.onset),
                         "evidence_span_id": f.evidence["span_id"]}
                        for f in sorted(findings, key=lambda f: f.onset["start"])],
        "causal_graph": {"edges": edges},
        "fix_set": {"operations": ops},
    }
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:  # contract: always exactly one JSON object on stdout
        log(f"[fatal] {e!r}")
        sys.stdout.write(json.dumps({"root_causes": [], "causal_graph": {"edges": []},
                                     "fix_set": {"operations": []}}))
