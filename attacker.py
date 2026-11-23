import re
import uuid
import random
from datetime import datetime, timezone
from typing import List, Dict, Optional
from pydantic import BaseModel, Field
from arena_core import (
    CorporatePersona,
    RedTeamArtifact,
    get_llm_client,
    get_api_key_pool,
    first_api_key,
)


# SANDBOX RULES

SAFE_BASE_DOMAINS = ("example.com", "example.org", "example.net")

URL_PATTERN = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
BARE_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|info|biz|ru|cn|xyz|top|us|uk|in|de|fr|app|dev|site|online|cloud|link|click|shop|club|support|work|tech|ai|me|tv|cc|ly|gl)\b",
    re.IGNORECASE,
)


def is_safe_domain(domain: str) -> bool:
    d = domain.lower().strip().rstrip(".")
    if d == "test" or d.endswith(".test"):
        return True
    return any(d == base or d.endswith("." + base) for base in SAFE_BASE_DOMAINS)


def _safe_domain_for(domain: str) -> str:
    if is_safe_domain(domain):
        return domain.lower().strip()
    label = re.sub(r"[^a-z0-9]+", "-", domain.lower()).strip("-") or "unknown"
    return f"{label}.test"


def _sanitize_address(address: str) -> str:
    if "<" in address and ">" in address:
        address = address.split("<", 1)[1].split(">", 1)[0].strip()
    if "@" not in address:
        return "unknown@unknown-sender.test"
    local_part, domain = address.rsplit("@", 1)
    local_part = re.sub(r"[^a-z0-9._+-]+", "", local_part.lower()) or "user"
    return f"{local_part}@{_safe_domain_for(domain)}"


def _scrub_text(text: str) -> str:
    text = URL_PATTERN.sub("[SIMULATED_LINK]", text)
    text = IPV4_PATTERN.sub("[REDACTED_IP]", text)

    def _bare(match: re.Match) -> str:
        return match.group(0) if is_safe_domain(match.group(0)) else "[SIMULATED_LINK]"

    return BARE_DOMAIN_PATTERN.sub(_bare, text)


def _clean_attachment_name(raw_meta: Optional[str]) -> Optional[str]:
    if not raw_meta:
        return None
    cleaned = raw_meta.strip()
    if cleaned.lower() in ("none", "none.sim", "n/a", "n_a.sim", "[no attachment].sim", "null", ""):
        return None
    fn_match = re.search(
        r"['\"](?:file_name|filename|attachment_name|simulated_filename)['\"]\s*:\s*['\"]([^'\"]+)['\"]",
        cleaned,
    )
    if fn_match:
        cleaned = fn_match.group(1)
    cleaned = re.sub(r"[\\/]+", "_", cleaned).strip(" []{}\"'")
    if not cleaned:
        return None
    if not cleaned.lower().endswith(".sim"):
        cleaned += ".sim"
    return cleaned


def _make_lookalike_domain(domain: str) -> str:
    d = domain.lower().strip()
    if d.endswith(".example.org"):
        return f"{d[:-len('.example.org')]}-portal.test"
    if d.endswith(".example.com"):
        return f"{d[:-len('.example.com')]}-verify.test"
    if d.endswith(".test"):
        return f"{d[:-len('.test')]}-support.test"
    return f"{d}-auth.test"


def assign_realistic_auth(email, target: CorporatePersona, is_phishing: bool) -> None:

    sender_dom = email.sender_address.split("@")[-1]
    protected = {"acme-corp.test", *{v.lower() for v in target.known_vendors}}
    r = random.random()
    if is_phishing:
        if sender_dom in protected:          # compromised legitimate account / vendor
            email.spf_status, email.dkim_status = "PASS", "PASS"
        elif r < 0.70:                       # attacker-owned lookalike, correctly configured
            email.spf_status, email.dkim_status = "PASS", "PASS"
        elif r < 0.90:
            email.spf_status, email.dkim_status = "SOFTFAIL", "NONE"
        else:
            email.spf_status, email.dkim_status = "FAIL", "FAIL"
    else:                                    # benign, with ~10% noisy-but-legitimate hard negatives
        if r < 0.90:
            email.spf_status, email.dkim_status = "PASS", "PASS"
        elif r < 0.95:
            email.spf_status, email.dkim_status = "SOFTFAIL", "PASS"
        else:
            email.spf_status, email.dkim_status = "PASS", "NONE"


# ZERO-TOKEN PROCEDURAL CORPORATE PERSONA GENERATOR

FIRST_NAMES = [
    "Aarav", "Mei", "Carlos", "Fatima", "Liam", "Sora", "Nadia", "Mateo",
    "Zara", "Kenji", "Amara", "Vikram", "Sofia", "Tariq", "Hannah", "Darius",
    "Ananya", "Lucas", "Yuki", "Omar", "Chloe", "Rohan", "Ines", "Samuel",
    "Kavya", "Noah", "Leila", "Jin", "Gabriela", "Idris", "Tessa", "Arjun",
    "Miriam", "Sebastian", "Noor", "Hector", "Amina", "Devon", "Sana", "Kiran",
]

LAST_NAMES = [
    "Sharma", "Tanaka", "Rodriguez", "Al-Mansoor", "O'Connor", "Kim", "Patel",
    "Fernandez", "Mensah", "Sato", "Kowalski", "Reddy", "Silva", "Hassan",
    "Lindqvist", "Bautista", "Chatterjee", "Moreau", "Nakamura", "Ibrahim",
    "Benitez", "Subramanian", "Vargas", "Okafor", "Sinha", "Delgado", "Park",
    "Mukherjee", "Alvarez", "Chaudhry", "Novak", "Bose", "Castillo", "Nair",
]

DEPT_CATALOG = {
    "Finance": {
        "roles": ["Accounts Payable Specialist", "Financial Controller", "Tax Compliance Lead", "Treasury Analyst"],
        "projects": ["Q4 Vendor Audit", "ERP Cloud Migration", "FY27 Budget Reconciliation", "SOX Control Review"],
        "vendors": ["globex-vendor.test", "netsuite-billing.example.com", "taxportal.example.org"],
    },
    "Engineering": {
        "roles": ["Principal DevOps Engineer", "Staff Backend Architect", "Site Reliability Lead", "Platform Security Engineer"],
        "projects": ["Zero-Trust IAM Rollout", "Kubernetes Cluster Upgrade", "CI/CD Pipeline Hardening", "API Gateway Migration"],
        "vendors": ["gitops-ci.example.org", "sec-tools.example.com", "cloud-registry.test"],
    },
    "Human Resources": {
        "roles": ["People Operations Partner", "Compensation & Benefits Manager", "Talent Acquisition Lead", "HRIS Administrator"],
        "projects": ["Annual Open Enrollment", "Global Payroll Harmonization", "Performance Cycle Rollout", "Remote Work Policy Update"],
        "vendors": ["workday-hr.test", "benefits-hub.example.org", "payroll-sync.example.com"],
    },
    "Legal & Compliance": {
        "roles": ["Senior Corporate Counsel", "Data Privacy Officer", "Contract Operations Manager", "Regulatory Compliance Specialist"],
        "projects": ["GDPR Data Mapping", "Enterprise MSA Renewal", "ISO-27001 Recertification", "Vendor Risk Assessment"],
        "vendors": ["docusign-legal.test", "compliance-vault.example.org", "ediscovery-pro.example.com"],
    },
    "Sales & Revenue": {
        "roles": ["Enterprise Account Director", "Revenue Operations Manager", "Strategic Partnerships Lead", "Solutions Engineering Manager"],
        "projects": ["Q4 Enterprise Pipeline Push", "CRM Territory Realignment", "Channel Partner Onboarding", "Annual Customer Summit"],
        "vendors": ["crm-cloud.test", "quote-engine.example.com", "partner-portal.example.org"],
    },
    "Procurement & Operations": {
        "roles": ["Strategic Sourcing Manager", "IT Asset & Licensing Specialist", "Supply Chain Coordinator", "Facilities Operations Lead"],
        "projects": ["SaaS License Consolidation", "Hardware Refresh Cycle", "Supplier SLA Renegotiation", "Office Access Upgrade"],
        "vendors": ["coupa-procure.test", "asset-track.example.org", "logistics-hub.example.com"],
    },
    "Security & IT": {
        "roles": ["IAM Operations Lead", "Corporate IT Systems Admin", "Threat Intelligence Analyst", "Endpoint Engineering Specialist"],
        "projects": ["Passkey & MFA Enforcement", "SSO Federation Cutover", "MDM Enrollment Audit", "Endpoint EDR Upgrade"],
        "vendors": ["okta-sso.test", "mdm-cloud.example.com", "siem-alerts.example.org"],
    },
}


def generate_procedural_persona(used_names: Optional[set] = None) -> CorporatePersona:
    for _ in range(50):
        full_name = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
        if used_names is None or full_name not in used_names:
            break
    if used_names is not None:
        used_names.add(full_name)

    manager_name = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
    while manager_name == full_name:
        manager_name = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"

    dept = random.choice(list(DEPT_CATALOG.keys()))
    spec = DEPT_CATALOG[dept]
    return CorporatePersona(
        employee_id=f"EMP-{random.randint(100, 999)}",
        full_name=full_name,
        role=random.choice(spec["roles"]),
        department=dept,
        manager_name=manager_name,
        recent_projects=random.sample(spec["projects"], k=2),
        known_vendors=random.sample(spec["vendors"], k=2),
    )


class _PersonaBatch(BaseModel):
    personas: List[CorporatePersona] = Field(
        description="Distinct corporate employee profiles across varied departments and seniority."
    )


class AdaptiveRedTeamAgent:
    def __init__(
        self,
        model: str = "openai/gpt-oss-120b",
        provider: str = "groq",
        realistic_auth: bool = False,
    ):
        self.provider = provider
        self.api_keys = get_api_key_pool(provider=provider)
        self.key_index = 0
        self.client = get_llm_client(provider=provider, api_key_override=first_api_key(self.api_keys))
        self.model = model
        self.realistic_auth = realistic_auth
        self.tactic_weights: Dict[str, float] = {
            "Authority / Executive Request": 1.0,
            "Routine Vendor Invoice": 1.0,
            "IT Credential / MFA Policy": 1.0,
            "HR Benefits / Compliance": 1.0,
            "SaaS Collaboration / Shared Document": 1.0,
            "Legal / Compliance Audit Notice": 1.0,
        }
        self.blocked_feedback_memory: List[str] = []
        self.successful_patterns: List[str] = []
        self.generated_names_history: List[str] = []
        self.last_tactic: str = ""
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

    def _sanitize_persona(self, persona: CorporatePersona) -> CorporatePersona:
        persona.employee_id = f"EMP-{random.randint(100, 999)}"
        persona.known_vendors = [
            _safe_domain_for(v.split("@")[-1]) for v in (persona.known_vendors or ["vendor-portal.test"])
        ]
        return persona

    async def generate_dynamic_personas(
        self,
        count: int = 12,
        org_domain: str = "acme-corp.test",
    ) -> List[CorporatePersona]:
        avoid_clause = ""
        if self.generated_names_history:
            avoid_clause = (
                "Do NOT reuse any of these previously generated names: "
                + ", ".join(self.generated_names_history[-30:])
                + ".\n"
            )

        system_prompt = (
            "You are a Corporate Org-Chart Generator for a cybersecurity phishing simulation.\n"
            f"Generate {count} distinct, realistic corporate employees working at '{org_domain}'.\n"
            "RULES:\n"
            "1. Span diverse departments and seniority levels.\n"
            "2. Use culturally diverse, realistic full names for both employees and their managers.\n"
            "3. Give each employee 2-3 specific active projects and 2-3 known vendor domains "
            "ending ONLY in .test, example.com, or example.org.\n"
            f"{avoid_clause}"
        )

        response = await self.client.beta.chat.completions.parse(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Generate {count} unique CorporatePersona profiles now."},
            ],
            response_format=_PersonaBatch,
            temperature=0.95,
        )

        batch = response.choices[0].message.parsed
        if batch is None or not batch.personas:
            raise ValueError("Persona generator returned no parsable profiles.")

        cleaned: List[CorporatePersona] = []
        for p in batch.personas:
            sanitized = self._sanitize_persona(p)
            self.generated_names_history.append(sanitized.full_name)
            cleaned.append(sanitized)
        return cleaned

    def _enforce_realism_and_sanitize(
        self,
        artifact: RedTeamArtifact,
        target: CorporatePersona,
        force_benign: bool,
    ) -> RedTeamArtifact:
        email = artifact.email
        email.body = _scrub_text(email.body)
        email.sender_display = _scrub_text(email.sender_display)
        email.subject = _scrub_text(email.subject)
        email.sender_address = _sanitize_address(email.sender_address)
        email.reply_to_address = _sanitize_address(email.reply_to_address)
        email.attachment_metadata = _clean_attachment_name(email.attachment_metadata)

        if force_benign:
            sender_dom = email.sender_address.split("@")[-1]
            valid_domains = {"acme-corp.test", *{v.lower() for v in target.known_vendors}}
            if sender_dom not in valid_domains:
                local = email.sender_address.split("@")[0]
                email.sender_address = f"{local}@acme-corp.test"
                email.reply_to_address = email.sender_address
            artifact.mitre_technique = "BENIGN"
            if self.realistic_auth:
                assign_realistic_auth(email, target, is_phishing=False)
            return artifact

        sender_local, sender_dom = email.sender_address.split("@", 1)
        protected_domains = {"acme-corp.test", *{v.lower() for v in target.known_vendors}}
        if sender_dom in protected_domains and random.random() > 0.45:
            lookalike_dom = _make_lookalike_domain(sender_dom)
            email.sender_address = f"{sender_local}@{lookalike_dom}"
            if email.reply_to_address.endswith(f"@{sender_dom}"):
                email.reply_to_address = email.sender_address

        has_link = "[SIMULATED_LINK]" in email.body
        has_attachment = bool(email.attachment_metadata)
        has_sensitive_ask = bool(
            re.search(
                r"\b(password|passkey|mfa|token|credential|login|sign[- ]in|wire|routing|bank|invoice|w-9|ssn)\b",
                email.body,
                re.IGNORECASE,
            )
        )
        if not (has_link or has_attachment or has_sensitive_ask):
            email.body = (
                email.body.rstrip()
                + "\n\nPlease review and confirm your account authorization via our portal: [SIMULATED_LINK]"
            )

        if self.realistic_auth:
            assign_realistic_auth(email, target, is_phishing=True)
        return artifact

    def select_next_tactic(self) -> str:
        tactics = list(self.tactic_weights.keys())
        weights = list(self.tactic_weights.values())
        return random.choices(tactics, weights=weights, k=1)[0]

    async def generate_campaign_email(
        self,
        target: CorporatePersona,
        force_benign: bool = False
    ) -> RedTeamArtifact:
        chosen_tactic = "Benign Operational Communication" if force_benign else self.select_next_tactic()
        self.last_tactic = chosen_tactic

        evolution_prompt = ""
        if not force_benign:
            if self.blocked_feedback_memory:
                recent_blocks = "\n".join(f"- {note}" for note in self.blocked_feedback_memory[-4:])
                evolution_prompt += (
                    f"\n[ADVERSARIAL ADAPTATION LOG — DEFENSES TO EVADE]\n"
                    f"Blocked reasons:\n{recent_blocks}\n"
                    f"Refine pretext to sound natural while keeping a realistic simulated attack vector."
                )
            if self.successful_patterns:
                recent_wins = "\n".join(f"- {win}" for win in self.successful_patterns[-2:])
                evolution_prompt += (
                    f"\n[WINNING PATTERNS]\n"
                    f"Previously bypassed:\n{recent_wins}"
                )

        if force_benign:
            mode_instructions = (
                "MODE: BENIGN CONTROL EMAIL.\n"
                "- Send from the target's manager (@acme-corp.test) or one of their exact known_vendors.\n"
                "- Discuss normal project updates without credential/wire harvesting or suspicious lookalike domains.\n"
                "- Set mitre_technique='BENIGN'."
            )
        else:
            mode_instructions = (
                "MODE: SIMULATED PHISHING ATTACK.\n"
                "- Mix lookalike external domains (e.g. '<vendor>-verify.test') with subtle compromised-vendor "
                "pretexts from one of the target's known_vendors.\n"
                "- MUST include at least one concrete simulated exploitation vector: either [SIMULATED_LINK] "
                "to harvest credentials/approvals, a simulated attachment ending in .sim, or a wire/token/credential request.\n"
                "- Set an accurate MITRE ATT&CK technique ID (e.g., T1566.001, T1566.002, T1598.003)."
            )

        system_prompt = (
            "You are a Red Team Adversarial Simulation Engine generating synthetic emails for a defensive AI benchmark.\n"
            "STRICT SAFETY & BENCHMARK RULES:\n"
            "1. Use ONLY fictional domains ending in .test, example.com, or example.org.\n"
            "2. NEVER generate real URLs or IP addresses. Use [SIMULATED_LINK] for any hyperlink.\n"
            "3. Put ONLY a raw email address in sender_address and reply_to_address (no display name or angle brackets).\n"
            "4. If attaching a file, attachment_metadata must be a single clean filename ending in .sim "
            "(e.g. 'Q4_Invoice.pdf.sim'), or null if there is no attachment.\n"
            "5. Keep body concise (80-130 words).\n"
            f"{mode_instructions}"
        )

        user_prompt = (
            f"Target Employee Profile:\n{target.model_dump_json()}\n\n"
            f"Selected Framing: {chosen_tactic}"
            f"{evolution_prompt}"
        )

        response = await self.client.beta.chat.completions.parse(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format=RedTeamArtifact,
            temperature=0.85,
        )

        usage = getattr(response, "usage", None)
        self.last_tokens = int(getattr(usage, "total_tokens", 0) or 0)

        artifact = response.choices[0].message.parsed
        if artifact is None:
            raise ValueError("Attacker model returned no parsable artifact.")
        artifact.email.message_id = f"sim-{uuid.uuid4().hex[:12]}"
        artifact.email.timestamp = datetime.now(timezone.utc).isoformat()
        artifact.is_phishing = not force_benign

        return self._enforce_realism_and_sanitize(artifact, target=target, force_benign=force_benign)

    def update_policy(self, artifact: RedTeamArtifact, defender_blocked: bool, defender_summary: str):
        if not artifact.is_phishing:
            return

        tactic = self.last_tactic
        if defender_blocked:
            self.blocked_feedback_memory.append(f"[{tactic}] Blocked because: {defender_summary}")
            if tactic in self.tactic_weights:
                self.tactic_weights[tactic] = max(0.2, self.tactic_weights[tactic] * 0.85)
        else:
            self.successful_patterns.append(f"[{tactic}] Bypassed defense: {artifact.attacker_rationale}")
            if tactic in self.tactic_weights:
                self.tactic_weights[tactic] = min(3.0, self.tactic_weights[tactic] * 1.25)
