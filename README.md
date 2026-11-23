# AI vs. AI Phishing Arena

A sandboxed adversarial simulation: a **red-team LLM** writes adaptive spearphishing emails against synthetic
employees, and a **blue-team defender** (five specialists, D1–D5) tries to catch them. Every round is labelled,
logged to SQLite and exportable as a JSONL dataset. **All traffic is synthetic**: no live URLs, IPs or real
domains (`.test` / `example.*` only; attachments are `.sim` metadata, never binaries).

## How it works

```
persona (procedural) → Red Team (6 pretexts, adaptive weights) → Sanitizer → Defender D1–D5 → verdict → log + feedback
```

| Specialist | Weight | What it checks |
|---|---|---|
| D1 Auth_Header_Inspector | 0.15 | SPF / DKIM failures, Reply-To domain mismatch |
| D2 Domain_Link_Forensics | 0.20 | lookalike / unknown sender domains, external `[SIMULATED_LINK]` lures |
| D3 Identity_Attachment_Guard | 0.15 | manager display-name spoofing, risky `.sim` attachment extensions |
| D4 Semantic_SOC_Adjudicator (LLM) | 0.50 | context-aware BEC / social-engineering analysis, with learned memory |
| D5 Confidence-Weighted Consensus | – | `score = max(Σ wᵢ·sᵢ, 0.85·max sᵢ)`; ALLOW < 0.42 ≤ QUARANTINE < 0.72 ≤ BLOCK |

Both agents learn in-run: the attacker re-weights pretexts (×1.25 on bypass, ×0.85 on block, clamp 0.2–3.0) and
sees recent block reasons; the defender turns misses and false alarms into prompt notes.

## Published run (`data/`)

100 rounds, 1 run, Groq, attacker `openai/gpt-oss-120b`, defender D4 `openai/gpt-oss-20b`, `--seed 1 --delay 6`.

| TP | FN | FP | TN | Precision | Recall | Accuracy | F1 |
|---|---|---|---|---|---|---|---|
| 75 | 0 | 3 | 22 | 96.2% | 100% | 97.0% | 98.0% |

Sandbox audit: 0 URL leaks, 0 IP leaks, 0 unsafe addresses.

### ⚠️ Read this before citing the numbers
In this run the attacker LLM also chose the SPF/DKIM results. **72 of 75 phishing emails had SPF *and* DKIM
failing; 0 of 25 benign emails had any failure**, and all 75 phishing senders were external lookalike domains
(no compromised-account/vendor cases). Header rules alone therefore almost separate the classes, so 100% recall
overstates real-world strength. Because the defender never missed, all pretext weights also decayed to the 0.2
floor, i.e. the attacker had no adaptation signal. Latency figures include rate-limit waits.

`python run_arena.py --realistic-auth` makes the *environment* assign SPF/DKIM (compromised accounts always
authenticate; attacker-owned lookalikes mostly do; ~10% of benign mail is noisy) to remove this shortcut.
**It is implemented and unit-tested but a full LLM re-run has not been done yet.**

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export GROQ_API_KEY=gsk_...              # or use --provider ollama / openai (see .env.example)

python run_arena.py --rounds 100 --seed 1 --delay 6 \
    --attacker-model openai/gpt-oss-120b --defender-model openai/gpt-oss-20b
python run_arena.py --rounds 100 --realistic-auth      # harder, leak-free benchmark

python evaluate.py --db phishing_arena_telemetry.db --out results.json   # metrics, windows, trend test, audits
python evaluate.py --db data/phishing_arena_telemetry.db --out /tmp/r.json   # reproduces the published numbers
```

`--seed` fixes personas, pretext sampling and the benign mix; LLM output is not deterministic.

### API / dashboard
```bash
python main.py        # http://127.0.0.1:8000  (serves front.html if present)
```
`GET /api/v1/health`, `GET /api/v1/arena/stats`, `GET /api/v1/arena/rounds`,
`POST /api/v1/arena/scan` (score a custom email, no logging), `POST /api/v1/arena/simulate-one`.

### Tests
```bash
python -m unittest -v test_arena      # no network needed; the LLM specialist is stubbed
```

## Repo layout
```
arena_core.py   schemas, LLM client factory, SQLite telemetry
attacker.py     red-team agent, sanitizer, procedural personas, realistic-auth mode
defender.py     D1–D5 defender and learning memory
run_arena.py    CLI simulation loop (retry/rate-limit handling, JSONL export)
evaluate.py     reproduces results.json from the telemetry DB
main.py         FastAPI service
front.html      single-file dashboard served at /
test_arena.py   unit tests (CI: .github/workflows/tests.yml)
data/           published run: telemetry DB, JSONL dataset, results.json
docs/           project deck (PowerPoint)
```

## Known issues / next steps
1. **D4 prompt contradiction → the 3 false positives.** Rule 2 asks for score ≥ 0.65 on *any* `[SIMULATED_LINK]`
   request, while rule 3 says routine internal mail is benign. All 3 FPs were internal mail with a portal or
   calendar link (D4 = 0.65–0.70). Fix: apply rule 2 only when the link is paired with a credential, MFA, wire or
   billing ask. Not changed here so the published run stays reproducible with this code.
2. Re-run with `--realistic-auth` and report those numbers alongside the original.
3. `export_rlhf_dataset()` writes every row in the DB; pass `run_id` to export a single run.
4. The "SFT" JSONL holds email + label + defender verdict, not chat-formatted instruction/response pairs.

## Safety
Offensive-style research, contained by design: all URLs/IPs/bare domains are rewritten to `[SIMULATED_LINK]` /
`[REDACTED_IP]`, sender/reply-to domains are forced to reserved `.test` / `example.*`, attachments are `.sim`
names only. Do not point this at real mail systems or real people.
