import json
import re
from typing import List
from pydantic import BaseModel, Field
from arena_core import (
    CorporatePersona,
    SimulatedEmailPayload,
    DefenderStageResult,
    BlueTeamVerdict,
    get_llm_client,
    get_api_key_pool,
    first_api_key,
)

RISKY_EXTENSIONS = (".exe", ".scr", ".js", ".vbs", ".iso", ".zip", ".html", ".bat", ".ps1", ".docm", ".xlsm")
INTERNAL_CORP_DOMAIN = "acme-corp.test"


class _SemanticSOCOutput(BaseModel):
    risk_score: float = Field(ge=0.0, le=1.0)
    flags: List[str]


def _real_attachment_name(metadata: str) -> str:
    name = metadata.strip().lower()
    if name.endswith(".sim"):
        name = name[:-4]
    return name


def _extract_domain(address: str) -> str:
    addr = address.strip().lower()
    if "<" in addr and ">" in addr:
        addr = addr.split("<", 1)[1].split(">", 1)[0].strip()
    return addr.split("@")[-1] if "@" in addr else addr


def _is_lookalike_domain(domain: str, trusted_domains: set) -> str:
    if domain in trusted_domains:
        return ""
    for trusted in trusted_domains:
        trusted_stem = trusted.split(".")[0]
        if len(trusted_stem) >= 5 and trusted_stem in domain:
            return f"Lookalike domain '{domain}' mimics trusted domain '{trusted}'"
    return ""


class LayeredBlueTeamAgent:
    """
    Five-Specialist Multi-Agent Defense Architecture (D1-D5):
      - D1 (Auth_Header_Inspector, w=0.15): SPF, DKIM, and Reply-To cross-domain alignment.
      - D2 (Domain_Link_Forensics, w=0.20): Lookalike/typosquat domains & external [SIMULATED_LINK] lures.
      - D3 (Identity_Attachment_Guard, w=0.15): Executive display-name spoofing & risky .sim attachments.
      - D4 (Semantic_SOC_Adjudicator, w=0.50): Context-aware LLM social engineering & BEC analysis.
      - D5 (Confidence_Weighted_Consensus): Replaces rigid 3-of-4 majority voting with calibrated
        weighted voting + high-confidence specialist escalation so single-vector attacks are never suppressed.

    Verdict bands (aggregate score): ALLOW < 0.42 <= QUARANTINE < 0.72 <= BLOCK.
    """

    def __init__(
        self,
        model: str = "openai/gpt-oss-20b",
        provider: str = "groq",
        block_threshold: float = 0.72,
        quarantine_threshold: float = 0.42,
    ):
        self.provider = provider
        self.api_keys = get_api_key_pool(provider=provider)
        self.key_index = 0
        self.client = get_llm_client(provider=provider, api_key_override=first_api_key(self.api_keys))
        self.model = model
        self.block_threshold = block_threshold
        self.quarantine_threshold = quarantine_threshold
        self.threat_intel_rules: List[str] = []
        self.false_positive_lessons: List[str] = []
        self.last_tokens: int = 0

    def rotate_api_key(self) -> bool:
        if len(self.api_keys) <= 1:
            return False
        self.key_index = (self.key_index + 1) % len(self.api_keys)
        self.client = get_llm_client(
            provider=self.provider,
            api_key_override=self.api_keys[self.key_index],
        )
        return True

    def _d1_auth_header_inspector(self, email: SimulatedEmailPayload) -> DefenderStageResult:
        score = 0.0
        flags = []

        if email.spf_status in ("FAIL", "SOFTFAIL"):
            score += 0.35
            flags.append(f"SPF authentication anomaly: {email.spf_status}")

        if email.dkim_status == "FAIL":
            score += 0.35
            flags.append("DKIM signature verification failed")

        sender_domain = _extract_domain(email.sender_address)
        reply_domain = _extract_domain(email.reply_to_address)
        if sender_domain != reply_domain:
            score += 0.50
            flags.append(f"Cross-domain Reply-To mismatch ({sender_domain} vs {reply_domain})")

        capped = min(1.0, score)
        return DefenderStageResult(
            stage_name="D1_Auth_Header_Inspector",
            specialist_id="D1",
            weight=0.15,
            risk_score=capped,
            flagged=capped >= 0.35,
            flags=flags if flags else ["SPF/DKIM and Reply-To headers aligned"],
        )

    def _d2_domain_link_forensics(
        self,
        email: SimulatedEmailPayload,
        recipient: CorporatePersona,
    ) -> DefenderStageResult:
        score = 0.0
        flags = []
        sender_domain = _extract_domain(email.sender_address)
        trusted_domains = {INTERNAL_CORP_DOMAIN, *(v.lower() for v in recipient.known_vendors)}

        lookalike_msg = _is_lookalike_domain(sender_domain, trusted_domains)
        if lookalike_msg:
            score += 0.65
            flags.append(lookalike_msg)
        elif sender_domain not in trusted_domains:
            score += 0.35
            flags.append(f"Unrecognized external sender domain: {sender_domain}")

        has_link = "[simulated_link]" in email.body.lower()
        has_credential_lure = bool(
            re.search(
                r"\b(password|passkey|mfa|token|credential|verify|confirm|sync|portal|wire|invoice|sign[- ]in)\b",
                email.body,
                re.IGNORECASE,
            )
        )
        if has_link and sender_domain != INTERNAL_CORP_DOMAIN:
            score += 0.15 if not has_credential_lure else 0.25
            flags.append("External email contains interactive portal link ([SIMULATED_LINK])")

        capped = min(1.0, score)
        return DefenderStageResult(
            stage_name="D2_Domain_Link_Forensics",
            specialist_id="D2",
            weight=0.20,
            risk_score=capped,
            flagged=capped >= 0.35,
            flags=flags if flags else ["Sender domain matches trusted corporate/vendor allowlist"],
        )

    def _d3_identity_attachment_guard(
        self,
        email: SimulatedEmailPayload,
        recipient: CorporatePersona,
    ) -> DefenderStageResult:
        score = 0.0
        flags = []
        sender_domain = _extract_domain(email.sender_address)
        trusted_domains = {INTERNAL_CORP_DOMAIN, *(v.lower() for v in recipient.known_vendors)}

        if (
            recipient.manager_name.lower() in email.sender_display.lower()
            and sender_domain != INTERNAL_CORP_DOMAIN
        ):
            score += 0.65
            flags.append(
                f"Executive/Manager display-name spoofing ('{email.sender_display}' via '{sender_domain}')"
            )

        if email.attachment_metadata:
            real_name = _real_attachment_name(email.attachment_metadata)
            if any(real_name.endswith(ext) for ext in RISKY_EXTENSIONS):
                score += 0.65
                flags.append(f"High-risk simulated attachment extension: {email.attachment_metadata}")
            elif sender_domain not in trusted_domains:
                score += 0.30
                flags.append(f"Attachment from untrusted external domain: {email.attachment_metadata}")

        capped = min(1.0, score)
        return DefenderStageResult(
            stage_name="D3_Identity_Attachment_Guard",
            specialist_id="D3",
            weight=0.15,
            risk_score=capped,
            flagged=capped >= 0.30,
            flags=flags if flags else ["No display-name spoofing or risky attachment detected"],
        )

    async def _d4_semantic_soc_adjudicator(
        self,
        email: SimulatedEmailPayload,
        recipient: CorporatePersona,
        prior_specialists: List[DefenderStageResult],
    ) -> DefenderStageResult:
        threat_context = ""
        if self.threat_intel_rules:
            threat_context += "\n[LEARNED THREAT SIGNATURES FROM MISSED BREACHES]\n" + "\n".join(
                f"- {r}" for r in self.threat_intel_rules[-6:]
            )
        if self.false_positive_lessons:
            threat_context += "\n[FALSE POSITIVE CALIBRATION NOTES]\n" + "\n".join(
                f"- {fp}" for fp in self.false_positive_lessons[-5:]
            )

        system_prompt = (
            "You are Specialist D4 (Senior SOC Semantic Analyst AI) evaluating an inbound email.\n"
            "CRITICAL DETECTION RULES:\n"
            "1. Domain & Identity Verification: Legitimate internal staff ONLY send from 'acme-corp.test'. "
            "Legitimate external vendors ONLY send from exact domains in recipient_context.known_vendors. "
            "Any hyphenated or modified lookalike (e.g., 'okta-sso-support.test', 'acme-corp-portal.test') "
            "is HIGH-RISK impersonation (score >= 0.75).\n"
            "2. Compromised-Vendor & BEC Detection: Even if sender matches a known vendor domain and SPF/DKIM pass, "
            "scrutinize requests asking the employee to click [SIMULATED_LINK], open attachments, verify MFA/SSO "
            "tokens, or update wire/billing records (score >= 0.65).\n"
            "3. Benign Baseline Calibration: Routine status updates or project coordination sent from "
            "'acme-corp.test' or exact known_vendors WITHOUT credential/wire/portal lures are benign (score <= 0.20)."
            f"{threat_context}"
        )

        payload_view = {
            "recipient_context": recipient.model_dump(),
            "specialist_d1_d3_findings": [s.model_dump() for s in prior_specialists],
            "inbound_email": email.model_dump(),
        }

        response = await self.client.beta.chat.completions.parse(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Evaluate this email event:\n{json.dumps(payload_view)}"},
            ],
            response_format=_SemanticSOCOutput,
            temperature=0.10,
        )

        usage = getattr(response, "usage", None)
        self.last_tokens = int(getattr(usage, "total_tokens", 0) or 0)

        parsed = response.choices[0].message.parsed
        if parsed is None:
            raise ValueError("Defender D4 model returned no parsable verdict.")

        return DefenderStageResult(
            stage_name="D4_Semantic_SOC_Adjudicator",
            specialist_id="D4",
            weight=0.50,
            risk_score=parsed.risk_score,
            flagged=parsed.risk_score >= 0.45,
            flags=parsed.flags if parsed.flags else ["No semantic social-engineering cues detected"],
        )

    async def evaluate_email(
        self,
        email: SimulatedEmailPayload,
        recipient: CorporatePersona,
    ) -> BlueTeamVerdict:
        d1 = self._d1_auth_header_inspector(email)
        d2 = self._d2_domain_link_forensics(email, recipient)
        d3 = self._d3_identity_attachment_guard(email, recipient)
        d4 = await self._d4_semantic_soc_adjudicator(email, recipient, [d1, d2, d3])

        specialists = [d1, d2, d3, d4]
        yes_votes = sum(1 for s in specialists if s.flagged)
        weighted_sum = sum(s.weight * s.risk_score for s in specialists)
        peak_specialist = max(s.risk_score for s in specialists)
        aggregate_score = round(min(1.0, max(weighted_sum, 0.85 * peak_specialist)), 3)

        if aggregate_score >= self.block_threshold:
            action = "BLOCK"
        elif aggregate_score >= self.quarantine_threshold:
            action = "QUARANTINE"
        else:
            action = "ALLOW"

        clean_phrases = (
            "aligned",
            "allowlist",
            "no display-name",
            "no semantic",
        )
        active_flags = [
            f"[{s.specialist_id}] {flag}"
            for s in specialists
            for flag in s.flags
            if not any(p in flag.lower() for p in clean_phrases)
        ]
        summary = (
            f"Action={action} (Score={aggregate_score}, Votes={yes_votes}/4). "
            f"Signals: {', '.join(active_flags[:3]) or 'Clean'}."
        )

        return BlueTeamVerdict(
            message_id=email.message_id,
            final_action=action,
            consensus_policy="D5_Confidence_Weighted_Escalation",
            specialist_votes_yes=yes_votes,
            aggregate_risk_score=aggregate_score,
            stage_breakdown=specialists,
            executive_summary=summary,
            extracted_iocs=[email.sender_address, email.reply_to_address],
        )

    def learn_from_incident(self, email: SimulatedEmailPayload, was_actual_phish: bool, verdict: BlueTeamVerdict):
        sender_domain = _extract_domain(email.sender_address)
        has_link = "[simulated_link]" in email.body.lower()
        has_att = bool(email.attachment_metadata)

        if was_actual_phish and verdict.final_action == "ALLOW":
            vector = (
                "link + attachment"
                if (has_link and has_att)
                else ("portal link" if has_link else ("attachment" if has_att else "pretexting"))
            )
            self.threat_intel_rules.append(
                f"BREACH LESSON: Missed phishing from '{email.sender_address}' (domain='{sender_domain}', "
                f"subject='{email.subject}', vector={vector}). Even when SPF/DKIM pass and tone is calm, "
                f"treat unsolicited external {vector} verification/sync requests as suspicious."
            )
        elif not was_actual_phish and verdict.final_action in ("BLOCK", "QUARANTINE"):
            self.false_positive_lessons.append(
                f"FALSE ALARM LESSON: Over-flagged benign mail from '{email.sender_address}' "
                f"('{email.subject}'). Allow routine project updates from internal 'acme-corp.test' "
                f"or exact known_vendors when no credential/wire harvesting is present."
            )
