import os
import json
import sqlite3
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from arena_core import (
    CorporatePersona,
    SimulatedEmailPayload,
    init_database,
    log_match_result,
    DB_PATH,
)
from attacker import AdaptiveRedTeamAgent, generate_procedural_persona
from defender import LayeredBlueTeamAgent

PROVIDER = os.environ.get("ARENA_PROVIDER", "groq")
ATTACKER_MODEL = os.environ.get("ARENA_ATTACKER_MODEL", "openai/gpt-oss-120b")
DEFENDER_MODEL = os.environ.get("ARENA_DEFENDER_MODEL", "openai/gpt-oss-20b")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_database()
    yield


app = FastAPI(
    title="AI vs. AI Phishing Arena & Defensive Shield",
    description="Multi-Agent Adversarial Simulation, D1-D5 Hybrid Consensus Defense & Telemetry API",
    version="2.1.0",
    lifespan=lifespan,
)

allowed_origins = os.environ.get("ARENA_CORS_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in allowed_origins if o.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)


class CustomScanRequest(BaseModel):
    sender_display: str = "External Support"
    sender_address: str = "support@okta-sso-support.test"
    reply_to_address: str = "support@okta-sso-support.test"
    spf_status: str = "PASS"
    dkim_status: str = "PASS"
    subject: str = "Action Required: Passkey & MFA Policy Sync"
    body: str = "Hi, please verify your MFA configuration via [SIMULATED_LINK] before EOD."
    attachment_metadata: Optional[str] = None
    recipient_name: str = "Arjun Sharma"
    recipient_role: str = "IAM Operations Lead"
    recipient_department: str = "Security & IT"
    recipient_manager: str = "Elena Rostova"
    known_vendors: list[str] = Field(default_factory=lambda: ["okta-sso.test", "mdm-cloud.example.com"])


class SimulateRoundRequest(BaseModel):
    force_benign: bool = False


def _classify(is_phishing: bool, flagged: bool) -> str:
    if is_phishing and flagged:
        return "TP_BLOCKED"
    if not is_phishing and not flagged:
        return "TN_ALLOWED"
    if not is_phishing and flagged:
        return "FP_FALSE_ALARM"
    return "FN_BREACHED"


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "provider": PROVIDER, "attacker": ATTACKER_MODEL, "defender": DEFENDER_MODEL}


@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    html_path = os.path.join(os.path.dirname(__file__), "front.html")
    if not os.path.exists(html_path):
        raise HTTPException(status_code=404, detail="front.html not found (dashboard file missing from repo)")
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()


@app.get("/api/v1/arena/stats")
def get_arena_stats():
    init_database()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    rows = cursor.execute(
        "SELECT is_phishing, outcome, chosen_tactic, department, risk_score, attacker_ms, defender_ms FROM arena_logs"
    ).fetchall()
    conn.close()

    total = len(rows)
    tp = sum(1 for r in rows if r[1] == "TP_BLOCKED")
    tn = sum(1 for r in rows if r[1] == "TN_ALLOWED")
    fp = sum(1 for r in rows if r[1] == "FP_FALSE_ALARM")
    fn = sum(1 for r in rows if r[1] == "FN_BREACHED")

    precision = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
    accuracy = round((tp + tn) / total, 4) if total else 0.0
    f1 = round((2 * precision * recall) / (precision + recall), 4) if (precision + recall) else 0.0

    by_tactic = {}
    by_department = {}
    for is_phish, outcome, tactic, dept, risk, atk_ms, def_ms in rows:
        if is_phish and tactic:
            t_entry = by_tactic.setdefault(tactic, {"total": 0, "blocked": 0, "breached": 0})
            t_entry["total"] += 1
            if outcome == "TP_BLOCKED":
                t_entry["blocked"] += 1
            else:
                t_entry["breached"] += 1

        d_name = dept or "General"
        d_entry = by_department.setdefault(d_name, {"total": 0, "correct": 0})
        d_entry["total"] += 1
        if outcome in ("TP_BLOCKED", "TN_ALLOWED"):
            d_entry["correct"] += 1

    return {
        "total_rounds": total,
        "confusion_matrix": {"TP": tp, "TN": tn, "FP": fp, "FN": fn},
        "metrics": {
            "precision": precision,
            "recall": recall,
            "accuracy": accuracy,
            "f1": f1,
        },
        "by_tactic": by_tactic,
        "by_department": by_department,
    }


@app.get("/api/v1/arena/rounds")
def list_rounds(limit: int = Query(25, ge=1, le=200), offset: int = Query(0, ge=0)):
    init_database()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    rows = cursor.execute(
        """
        SELECT round_id, timestamp, message_id, target_employee, department,
               is_phishing, chosen_tactic, mitre_technique, defender_action,
               risk_score, outcome, raw_artifact_json, raw_verdict_json
        FROM arena_logs
        ORDER BY round_id DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    ).fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append({
            "round_id": r[0],
            "timestamp": r[1],
            "message_id": r[2],
            "target_employee": r[3],
            "department": r[4],
            "is_phishing": bool(r[5]),
            "chosen_tactic": r[6],
            "mitre_technique": r[7],
            "defender_action": r[8],
            "risk_score": r[9],
            "outcome": r[10],
            "artifact": json.loads(r[11]) if r[11] else {},
            "verdict": json.loads(r[12]) if r[12] else {},
        })
    return {"rounds": results}


@app.post("/api/v1/arena/scan")
async def scan_custom_email(req: CustomScanRequest):
    try:
        blue_team = LayeredBlueTeamAgent(model=DEFENDER_MODEL, provider=PROVIDER)
    except ValueError as exc:  # missing API key / bad provider
        raise HTTPException(status_code=503, detail=str(exc))
    persona = CorporatePersona(
        employee_id="EMP-LIVE",
        full_name=req.recipient_name,
        role=req.recipient_role,
        department=req.recipient_department,
        manager_name=req.recipient_manager,
        recent_projects=["Live Security Inspection"],
        known_vendors=req.known_vendors,
    )
    email = SimulatedEmailPayload(
        message_id="live-scan-preview",
        timestamp="2026-11-21T00:00:00Z",
        sender_display=req.sender_display,
        sender_address=req.sender_address,
        reply_to_address=req.reply_to_address,
        spf_status=req.spf_status if req.spf_status in ("PASS", "SOFTFAIL", "FAIL", "NONE") else "NONE",
        dkim_status=req.dkim_status if req.dkim_status in ("PASS", "FAIL", "NONE") else "NONE",
        subject=req.subject,
        body=req.body,
        attachment_metadata=req.attachment_metadata,
    )
    try:
        verdict = await blue_team.evaluate_email(email=email, recipient=persona)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Defender model call failed: {type(exc).__name__}")
    return verdict.model_dump()


@app.post("/api/v1/arena/simulate-one")
async def simulate_single_round(req: SimulateRoundRequest):
    init_database()
    try:
        red_team = AdaptiveRedTeamAgent(model=ATTACKER_MODEL, provider=PROVIDER)
        blue_team = LayeredBlueTeamAgent(model=DEFENDER_MODEL, provider=PROVIDER)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    target = generate_procedural_persona()

    try:
        artifact = await red_team.generate_campaign_email(target=target, force_benign=req.force_benign)
        verdict = await blue_team.evaluate_email(email=artifact.email, recipient=target)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Model call failed: {type(exc).__name__}")

    outcome = _classify(artifact.is_phishing, verdict.final_action in ("BLOCK", "QUARANTINE"))

    log_match_result(
        artifact=artifact,
        verdict=verdict,
        attacker_model=red_team.model,
        defender_model=blue_team.model,
        outcome=outcome,
        target_name=target.full_name,
        department=target.department,
        run_id="live-ui",
        chosen_tactic=red_team.last_tactic,
    )
    return {
        "target": target.model_dump(),
        "artifact": artifact.model_dump(),
        "verdict": verdict.model_dump(),
        "outcome": outcome,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
