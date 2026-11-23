import os
import sqlite3
from datetime import datetime, timezone
from typing import List, Literal, Optional
from openai import AsyncOpenAI
from pydantic import BaseModel, Field

DB_PATH = os.environ.get("ARENA_DB_PATH", "phishing_arena_telemetry.db")
SCHEMA_VERSION = "2.1.0"


# LLM CLIENT FACTORY (GROQ / OLLAMA / OPENAI)


def get_llm_client(provider: str = "groq", api_key_override: Optional[str] = None) -> AsyncOpenAI:
    provider = provider.lower().strip()
    if provider == "groq":
        raw_keys = api_key_override or os.environ.get("GROQ_API_KEYS") or os.environ.get("GROQ_API_KEY")
        if not raw_keys:
            raise ValueError("GROQ_API_KEY (or GROQ_API_KEYS) environment variable is not set.")
        api_key = raw_keys.split(",")[0].strip()
        return AsyncOpenAI(
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1",
            max_retries=0,
        )
    elif provider == "ollama":
        return AsyncOpenAI(
            api_key="ollama",
            base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
            max_retries=0,
        )
    elif provider == "openai":
        api_key = api_key_override or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable is not set.")
        return AsyncOpenAI(api_key=api_key, max_retries=0)
    else:
        raise ValueError(f"Unsupported provider '{provider}'. Use 'groq', 'ollama', or 'openai'.")


def get_api_key_pool(provider: str = "groq") -> List[str]:
    provider = provider.lower().strip()
    if provider == "groq":
        raw = os.environ.get("GROQ_API_KEYS") or os.environ.get("GROQ_API_KEY") or ""
        return [k.strip() for k in raw.split(",") if k.strip()]
    if provider == "openai":
        raw = os.environ.get("OPENAI_API_KEYS") or os.environ.get("OPENAI_API_KEY") or ""
        return [k.strip() for k in raw.split(",") if k.strip()]
    return ["ollama"]


def first_api_key(pool: List[str]) -> Optional[str]:
    return pool[0] if pool else None


# DATA CONTRACTS (STRICT ISOLATION & EXPLAINABILITY)

class CorporatePersona(BaseModel):
    employee_id: str
    full_name: str
    role: str
    department: str
    manager_name: str
    recent_projects: List[str]
    known_vendors: List[str]


class SimulatedEmailPayload(BaseModel):
    message_id: str
    timestamp: str
    sender_display: str
    sender_address: str
    reply_to_address: str
    spf_status: Literal["PASS", "SOFTFAIL", "FAIL", "NONE"]
    dkim_status: Literal["PASS", "FAIL", "NONE"]
    subject: str
    body: str = Field(description="Must ONLY use [SIMULATED_LINK] placeholders. Zero live URLs.")
    attachment_metadata: Optional[str] = Field(
        default=None,
        description="Simulated filename/type, e.g., 'Q3_Invoice.pdf.sim'"
    )


class RedTeamArtifact(BaseModel):
    email: SimulatedEmailPayload
    is_phishing: bool
    mitre_technique: str = Field(description="e.g., T1566.001 Spearphishing Attachment, or BENIGN")
    psychological_lever: str = Field(description="e.g., Authority, Urgency, Scarcity, Routine")
    attacker_rationale: str


class DefenderStageResult(BaseModel):
    stage_name: str
    specialist_id: str = Field(default="D0", description="Specialist identifier: D1, D2, D3, D4")
    weight: float = Field(default=0.25, ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=1.0)
    flagged: bool = Field(default=False, description="Binary specialist vote")
    flags: List[str]


class BlueTeamVerdict(BaseModel):
    message_id: str
    final_action: Literal["ALLOW", "QUARANTINE", "BLOCK"]
    consensus_policy: str = Field(default="D5_Confidence_Weighted_Escalation")
    specialist_votes_yes: int = Field(default=0, ge=0, le=4)
    aggregate_risk_score: float = Field(ge=0.0, le=1.0)
    stage_breakdown: List[DefenderStageResult]
    executive_summary: str
    extracted_iocs: List[str]


# TELEMETRY & DATASET STORAGE


EXTRA_COLUMNS = {
    "run_id": "TEXT",
    "chosen_tactic": "TEXT",
    "department": "TEXT",
    "attacker_ms": "REAL",
    "defender_ms": "REAL",
    "attacker_tokens": "INTEGER",
    "defender_tokens": "INTEGER",
    "schema_version": "TEXT",
}


def init_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS arena_logs (
            round_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            message_id TEXT,
            target_employee TEXT,
            department TEXT,
            is_phishing INTEGER,
            mitre_technique TEXT,
            psychological_lever TEXT,
            attacker_model TEXT,
            defender_model TEXT,
            defender_action TEXT,
            risk_score REAL,
            outcome TEXT,
            raw_artifact_json TEXT,
            raw_verdict_json TEXT,
            run_id TEXT,
            chosen_tactic TEXT,
            attacker_ms REAL,
            defender_ms REAL,
            attacker_tokens INTEGER,
            defender_tokens INTEGER,
            schema_version TEXT
        )
    """)
    existing = {row[1] for row in cursor.execute("PRAGMA table_info(arena_logs)")}
    for col, col_type in EXTRA_COLUMNS.items():
        if col not in existing:
            cursor.execute(f"ALTER TABLE arena_logs ADD COLUMN {col} {col_type}")
    conn.commit()
    conn.close()


def log_match_result(
    artifact: RedTeamArtifact,
    verdict: BlueTeamVerdict,
    attacker_model: str,
    defender_model: str,
    outcome: str,
    target_name: str,
    department: str = "General",
    run_id: Optional[str] = None,
    chosen_tactic: Optional[str] = None,
    attacker_ms: Optional[float] = None,
    defender_ms: Optional[float] = None,
    attacker_tokens: Optional[int] = None,
    defender_tokens: Optional[int] = None,
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO arena_logs (
            timestamp, message_id, target_employee, department, is_phishing,
            mitre_technique, psychological_lever, attacker_model,
            defender_model, defender_action, risk_score, outcome,
            raw_artifact_json, raw_verdict_json,
            run_id, chosen_tactic, attacker_ms, defender_ms,
            attacker_tokens, defender_tokens, schema_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now(timezone.utc).isoformat(),
        artifact.email.message_id,
        target_name,
        department,
        int(artifact.is_phishing),
        artifact.mitre_technique,
        artifact.psychological_lever,
        attacker_model,
        defender_model,
        verdict.final_action,
        verdict.aggregate_risk_score,
        outcome,
        artifact.model_dump_json(),
        verdict.model_dump_json(),
        run_id,
        chosen_tactic,
        attacker_ms,
        defender_ms,
        attacker_tokens,
        defender_tokens,
        SCHEMA_VERSION,
    ))
    conn.commit()
    conn.close()
