import argparse
import json
import re
import sqlite3
from collections import defaultdict
from statistics import mean, variance

from attacker import URL_PATTERN, IPV4_PATTERN, is_safe_domain


def _safe_div(a, b):
    return a / b if b else 0.0


def evaluate(db_path: str, window: int = 10, run_id=None) -> dict:
    conn = sqlite3.connect(db_path)
    q = ("SELECT is_phishing, outcome, chosen_tactic, attacker_ms, defender_ms, attacker_tokens, "
         "defender_tokens, raw_artifact_json, run_id FROM arena_logs")
    params = ()
    if run_id:
        q += " WHERE run_id = ?"
        params = (run_id,)
    rows = conn.execute(q + " ORDER BY round_id", params).fetchall()
    conn.close()

    n = len(rows)
    tp = sum(r[1] == "TP_BLOCKED" for r in rows)
    fn = sum(r[1] == "FN_BREACHED" for r in rows)
    fp = sum(r[1] == "FP_FALSE_ALARM" for r in rows)
    tn = sum(r[1] == "TN_ALLOWED" for r in rows)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)

    windows = []
    for i in range(0, n, window):
        chunk = rows[i:i + window]
        c_tp = sum(r[1] == "TP_BLOCKED" for r in chunk)
        c_fn = sum(r[1] == "FN_BREACHED" for r in chunk)
        c_tn = sum(r[1] == "TN_ALLOWED" for r in chunk)
        phish = c_tp + c_fn
        windows.append({
            "bucket": i // window + 1,
            "n": len(chunk),
            "accuracy": (c_tp + c_tn) / len(chunk),
            "recall": _safe_div(c_tp, phish),
            "bypass": _safe_div(c_fn, phish),
        })

    accs = [w["accuracy"] for w in windows]
    trend_t = trend_p = None
    if len(accs) >= 4:  # first half vs second half, Welch t-test (second - first)
        from scipy import stats
        half = len(accs) // 2
        res = stats.ttest_ind(accs[half:], accs[:half], equal_var=False)
        trend_t, trend_p = float(res.statistic), float(res.pvalue)
    var = variance(accs) if len(accs) > 1 else None

    tactic = defaultdict(lambda: [0, 0])
    for r in rows:
        if r[0] and r[2]:
            tactic[r[2]][0] += 1
            tactic[r[2]][1] += r[1] == "FN_BREACHED"
    by_tactic = {k: {"n": v[0], "bypass_rate": v[1] / v[0]} for k, v in tactic.items()}

    def m(idx):
        vals = [r[idx] for r in rows if r[idx] is not None]
        return mean(vals) if vals else None

    atk_ms, def_ms = m(3), m(4)

    url_leaks = ip_leaks = unsafe = 0
    audit = {"phish_auth_any_fail": 0, "phish_auth_both_fail": 0, "benign_auth_any_fail": 0,
             "phish_from_trusted_domain": 0}
    for r in rows:
        email = json.loads(r[7])["email"]
        any_fail = email["spf_status"] in ("FAIL", "SOFTFAIL") or email["dkim_status"] == "FAIL"
        both_fail = email["spf_status"] == "FAIL" and email["dkim_status"] == "FAIL"
        if r[0]:
            audit["phish_auth_any_fail"] += any_fail
            audit["phish_auth_both_fail"] += both_fail
            dom = email["sender_address"].split("@")[-1]
            audit["phish_from_trusted_domain"] += dom == "acme-corp.test"
        else:
            audit["benign_auth_any_fail"] += any_fail
        text = f"{email['subject']}\n{email['body']}"
        url_leaks += bool(URL_PATTERN.search(text))
        ip_leaks += bool(IPV4_PATTERN.search(text))
        for addr in (email["sender_address"], email["reply_to_address"]):
            if not is_safe_domain(addr.split("@")[-1]):
                unsafe += 1

    return {
        "n": n, "window": window, "TP": tp, "FN": fn, "FP": fp, "TN": tn,
        "phish": tp + fn, "benign": tn + fp,
        "precision": precision, "recall": recall,
        "accuracy": _safe_div(tp + tn, n), "f1": f1,
        "error_rate": _safe_div(fp + fn, n), "specificity": _safe_div(tn, tn + fp),
        "runs": len({r[8] for r in rows}),
        "windows": windows, "trend_t": trend_t, "trend_p": trend_p, "variance": var,
        "by_tactic": by_tactic,
        "attacker_ms": atk_ms, "defender_ms": def_ms,
        "attacker_tokens": m(5), "defender_tokens": m(6),
        "round_ms": (atk_ms or 0) + (def_ms or 0),
        "url_leaks": url_leaks, "ip_leaks": ip_leaks, "unsafe_addresses": unsafe,
        "header_leak_audit": audit,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="phishing_arena_telemetry.db")
    ap.add_argument("--out", default="results.json")
    ap.add_argument("--window", type=int, default=10)
    ap.add_argument("--run-id", default=None)
    a = ap.parse_args()
    res = evaluate(a.db, a.window, a.run_id)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    print(f"{res['n']} rounds | recall {res['recall']:.3f} precision {res['precision']:.3f} "
          f"accuracy {res['accuracy']:.3f} -> {a.out}")
