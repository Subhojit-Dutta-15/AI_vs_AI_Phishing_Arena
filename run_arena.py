import os
import re
import time
import random
import asyncio
import argparse
import json
import sqlite3
import uuid
from typing import List, Optional
from openai import RateLimitError
from arena_core import CorporatePersona, init_database, log_match_result, DB_PATH
from attacker import AdaptiveRedTeamAgent, generate_procedural_persona
from defender import LayeredBlueTeamAgent

PROVIDER = os.environ.get("ARENA_PROVIDER", "groq")

DEFAULT_MODELS = {
    "groq": {
        "attacker": "openai/gpt-oss-120b",
        "defender": "openai/gpt-oss-20b",
    },
    "ollama": {
        "attacker": "llama3.1:8b",
        "defender": "qwen2.5:14b",
    },
    "openai": {
        "attacker": "gpt-4o-mini",
        "defender": "gpt-4o-mini",
    },
}


def export_rlhf_dataset(output_file: str = "defender_sft_dataset.jsonl", run_id: Optional[str] = None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = "SELECT is_phishing, raw_artifact_json, raw_verdict_json, outcome, department FROM arena_logs"
    params: tuple = ()
    if run_id:
        query += " WHERE run_id = ?"
        params = (run_id,)
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    with open(output_file, "w", encoding="utf-8") as f:
        for is_phish, art_json, verd_json, outcome, dept in rows:
            artifact = json.loads(art_json)
            verdict = json.loads(verd_json)
            record = {
                "input_email": artifact["email"],
                "department": dept or "General",
                "ground_truth_label": "PHISHING" if is_phish else "BENIGN",
                "mitre_technique": artifact["mitre_technique"],
                "defender_verdict": verdict["final_action"],
                "defender_score": verdict["aggregate_risk_score"],
                "arena_outcome": outcome,
            }
            f.write(json.dumps(record) + "\n")
    print(f"Exported {len(rows)} training records to {output_file}")


def _extract_retry_seconds(exc: Exception, default_wait: float = 12.0) -> float:
    resp = getattr(exc, "response", None)
    if resp is not None:
        ra = resp.headers.get("retry-after")
        if ra:
            try:
                return float(ra) + 1.0
            except ValueError:
                pass
    match = re.search(r"try again in\s+(\d+(?:\.\d+)?)s", str(exc), re.IGNORECASE)
    if match:
        return float(match.group(1)) + 1.0
    return default_wait


async def with_retry(make_call, rotate_fn=None, attempts: int = 5):
    for attempt in range(attempts):
        try:
            return await make_call()
        except RateLimitError as exc:
            err_msg = str(exc)
            if "tokens per day" in err_msg.lower() or "requests per day" in err_msg.lower():
                if rotate_fn and rotate_fn():
                    print("  [Quota] Daily limit hit on current key; rotated to next API key.")
                    continue
                raise RuntimeError(
                    "Daily token/request limit reached on provider. Switch models or add backup keys."
                ) from exc

            if attempt == attempts - 1:
                raise
            if rotate_fn and rotate_fn():
                print("  [TPM Limit] Rotated to backup API key.")
                await asyncio.sleep(0.5)
                continue

            wait_s = _extract_retry_seconds(exc, default_wait=10.0 * (attempt + 1))
            print(f"  [Rate Limit] Waiting {wait_s:.1f}s for TPM bucket to refill...")
            await asyncio.sleep(wait_s)
        except Exception:
            if attempt == attempts - 1:
                raise
            await asyncio.sleep(2.0 * (2 ** attempt))
    raise RuntimeError(f"with_retry: all {attempts} attempts exhausted")


def _ratio(num: int, den: int) -> str:
    return f"{100 * num / den:.1f}%" if den else "n/a"


async def run_simulation(
    total_rounds: int = 10,
    provider: str = PROVIDER,
    seed=None,
    persona_mode: str = "procedural",
    pool_size: int = 12,
    round_delay: float = 5.0,
    attacker_model: Optional[str] = None,
    defender_model: Optional[str] = None,
    realistic_auth: bool = False,
):
    if seed is not None:
        random.seed(seed)
    init_database()
    models = DEFAULT_MODELS.get(provider, DEFAULT_MODELS["groq"])
    atk_model = attacker_model or models["attacker"]
    def_model = defender_model or models["defender"]
    run_id = uuid.uuid4().hex[:8]

    red_team = AdaptiveRedTeamAgent(model=atk_model, provider=provider, realistic_auth=realistic_auth)
    blue_team = LayeredBlueTeamAgent(model=def_model, provider=provider)

    print(
        f"Starting AI vs. AI Phishing Arena v2.1 | Run={run_id} | Provider={provider.upper()} | "
        f"Attacker={red_team.model} | Defender={blue_team.model} (D1-D5 Consensus) | "
        f"Rounds={total_rounds} | PersonaMode={persona_mode} | PacingDelay={round_delay}s | "
        f"RealisticAuth={realistic_auth}\n"
    )

    used_names = set()
    llm_pool: List[CorporatePersona] = []
    if persona_mode == "llm-pool":
        print(f"Synthesizing {pool_size} LLM corporate personas in 1 batch call...")
        llm_pool = await with_retry(
            lambda: red_team.generate_dynamic_personas(count=pool_size),
            rotate_fn=red_team.rotate_api_key,
        )
        print(f"LLM target pool ready ({len(llm_pool)} unique employees).\n")

    metrics = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    skipped = 0

    for r in range(1, total_rounds + 1):
        round_start = time.perf_counter()
        try:
            if persona_mode == "llm-pool" and llm_pool:
                target = random.choice(llm_pool)
            else:
                target = generate_procedural_persona(used_names=used_names)

            is_benign = random.random() < 0.30

            t0 = time.perf_counter()
            artifact = await with_retry(
                lambda: red_team.generate_campaign_email(target=target, force_benign=is_benign),
                rotate_fn=red_team.rotate_api_key,
            )
            attacker_ms = (time.perf_counter() - t0) * 1000
            attacker_tokens = red_team.last_tokens
            chosen_tactic = red_team.last_tactic

            t1 = time.perf_counter()
            verdict = await with_retry(
                lambda: blue_team.evaluate_email(email=artifact.email, recipient=target),
                rotate_fn=blue_team.rotate_api_key,
            )
            defender_ms = (time.perf_counter() - t1) * 1000
            defender_tokens = blue_team.last_tokens
        except RuntimeError as fatal_exc:
            print(f"\n[STOPPED at Round {r:02d}] {fatal_exc}")
            break
        except Exception as exc:
            skipped += 1
            print(f"[Round {r:02d}] SKIPPED after retries: {type(exc).__name__}: {exc}")
            continue

        defender_flagged = verdict.final_action in ("BLOCK", "QUARANTINE")

        if artifact.is_phishing and defender_flagged:
            outcome = "TP_BLOCKED"
            metrics["TP"] += 1
        elif not artifact.is_phishing and not defender_flagged:
            outcome = "TN_ALLOWED"
            metrics["TN"] += 1
        elif not artifact.is_phishing and defender_flagged:
            outcome = "FP_FALSE_ALARM"
            metrics["FP"] += 1
        else:
            outcome = "FN_BREACHED"
            metrics["FN"] += 1

        red_team.update_policy(artifact, defender_flagged, verdict.executive_summary)
        blue_team.learn_from_incident(artifact.email, artifact.is_phishing, verdict)

        log_match_result(
            artifact=artifact,
            verdict=verdict,
            attacker_model=red_team.model,
            defender_model=blue_team.model,
            outcome=outcome,
            target_name=target.full_name,
            department=target.department,
            run_id=run_id,
            chosen_tactic=chosen_tactic,
            attacker_ms=attacker_ms,
            defender_ms=defender_ms,
            attacker_tokens=attacker_tokens,
            defender_tokens=defender_tokens,
        )

        print(
            f"[Round {r:02d}] Target={target.full_name} ({target.department}) | "
            f"Truth={'PHISH' if artifact.is_phishing else 'BENIGN'} | "
            f"Tactic={chosen_tactic} | Votes={verdict.specialist_votes_yes}/4 | "
            f"Action={verdict.final_action} ({verdict.aggregate_risk_score}) -> {outcome}"
        )

        if round_delay > 0 and r < total_rounds:
            elapsed = time.perf_counter() - round_start
            if elapsed < round_delay:
                await asyncio.sleep(round_delay - elapsed)

    tp, tn, fp, fn = metrics["TP"], metrics["TN"], metrics["FP"], metrics["FN"]
    print("\nFinal Arena Metrics:", metrics, f"| skipped rounds: {skipped}")
    print(
        f"Precision {_ratio(tp, tp + fp)} | Recall {_ratio(tp, tp + fn)} | "
        f"Accuracy {_ratio(tp + tn, tp + tn + fp + fn)}"
    )
    print("Final pretext weights:", {k: round(v, 2) for k, v in red_team.tactic_weights.items()})
    export_rlhf_dataset()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI vs. AI Phishing Arena v2.1")
    parser.add_argument("--rounds", type=int, default=10, help="rounds in this run")
    parser.add_argument("--provider", default=PROVIDER, choices=["groq", "ollama", "openai"])
    parser.add_argument("--seed", type=int, default=None,
                        help="seeds personas/tactics/benign mix only; LLM outputs are not deterministic")
    parser.add_argument(
        "--persona-mode",
        default="procedural",
        choices=["procedural", "llm-pool"],
        help="'procedural' creates unique employees locally (0 API tokens); 'llm-pool' uses 1 LLM batch call",
    )
    parser.add_argument("--pool-size", type=int, default=12, help="personas in llm-pool mode")
    parser.add_argument("--delay", type=float, default=5.0, help="minimum seconds per round for rate-limit pacing")
    parser.add_argument("--attacker-model", default=None, help="override attacker model ID")
    parser.add_argument("--defender-model", default=None, help="override defender model ID")
    parser.add_argument("--realistic-auth", action="store_true",
                        help="environment (not the attacker LLM) assigns SPF/DKIM results; avoids the header label leak")
    args = parser.parse_args()
    asyncio.run(
        run_simulation(
            total_rounds=args.rounds,
            provider=args.provider,
            seed=args.seed,
            persona_mode=args.persona_mode,
            pool_size=args.pool_size,
            round_delay=args.delay,
            attacker_model=args.attacker_model,
            defender_model=args.defender_model,
            realistic_auth=args.realistic_auth,
        )
    )
