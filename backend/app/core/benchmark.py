from typing import Any, Dict, List, Optional


class LegalBenchmarkEngine:
    """
    Comparative Cyberstalking & Jurisprudence Benchmark Engine.
    Correlates detected behavioral typologies against:
      1. Historical 1999 US DOJ Cyberstalking Report benchmarks.
      2. Modern Indian Criminal Code (Bharatiya Nyaya Sanhita BNS Sec. 78).
      3. Indian Information Technology Act (Sections 66E, 66D, 67).
      4. United States Federal Stalking Code (18 U.S.C. § 2261A).
    """

    DOJ_1999_REFERENCE = {
        "report_title": "1999 DOJ Report: Cyberstalking: A New Challenge for Law Enforcement and Industry",
        "issuing_body": "United States Department of Justice (Vice President Al Gore Directive)",
        "year": 1999,
        "historical_context": (
            "First major federal governmental recognition of online stalking as a precursor to physical violence. "
            "Highlighted the anonymity of the internet, asymmetric effort (stalker expends minimal effort while "
            "terrorizing the victim), lack of geographical boundaries, and the escalation from digital messages "
            "to physical confrontation (e.g., the landmark 1998 Dellapenta cyber-solicitation case)."
        ),
        "key_historical_findings": [
            "Inability of conventional domestic violence restraining orders to deter online contact across state lines.",
            "Stalkers frequently forge header information or route communications through open mail relays.",
            "Online harassment rapidly escalates when the victim ignores or blocks initial contacts.",
            "Stalkers exploit third parties via doxxing/bulletin boards to carry out secondary harassment."
        ]
    }

    STATUTORY_DATABASE = {
        "BNS_78": {
            "jurisdiction": "India",
            "statute": "Bharatiya Nyaya Sanhita (BNS), 2023 - Section 78 (Stalking)",
            "supersedes": "Indian Penal Code (IPC) Section 354D",
            "statutory_text": (
                "(1) Any man who— (i) follows a woman and contacts, or attempts to contact such woman to foster "
                "personal interaction repeatedly despite a clear indication of disinterest by such woman; or "
                "(ii) monitors the use by a woman of the internet, email or any other form of electronic communication, "
                "commits the offence of stalking."
            ),
            "penalties": "First conviction: Imprisonment up to 3 years and fine; Second conviction: Imprisonment up to 5 years and fine.",
            "bailable": "Bailable for 1st offense; Non-bailable for subsequent convictions.",
            "triggers_on": ["Persistent Pursuit", "Surveillance & Monitoring"]
        },
        "IT_ACT_66E": {
            "jurisdiction": "India",
            "statute": "Information Technology Act, 2000 - Section 66E (Violation of Privacy)",
            "statutory_text": (
                "Punishment for violation of privacy: Whoever, intentionally or knowingly captures, publishes or "
                "transmits the image of a private area of any person without his or her consent, violating privacy."
            ),
            "penalties": "Imprisonment up to 3 years or fine not exceeding two lakh rupees, or both.",
            "bailable": "Bailable offense.",
            "triggers_on": ["Doxxing & Impersonation", "Threats & Intimidation"]
        },
        "IT_ACT_67": {
            "jurisdiction": "India",
            "statute": "Information Technology Act, 2000 - Section 67 (Publishing Obscene Material)",
            "statutory_text": (
                "Punishment for publishing or transmitting obscene material in electronic form: Whoever publishes or transmits "
                "or causes to be published or transmitted in the electronic form, any material which is lascivious or appeals to the prurient interest."
            ),
            "penalties": "First conviction: Imprisonment up to 3 years and fine up to 5 lakh rupees.",
            "bailable": "Cognizable and Bailable (1st offense).",
            "triggers_on": ["Threats & Intimidation", "Doxxing & Impersonation"]
        },
        "IT_ACT_66D": {
            "jurisdiction": "India",
            "statute": "Information Technology Act, 2000 - Section 66D (Cheating by Personation Using Computer Resource)",
            "statutory_text": (
                "Whoever, by means of any communication device or computer resource, cheats by personating, shall be punished."
            ),
            "penalties": "Imprisonment up to 3 years and fine up to one lakh rupees.",
            "bailable": "Cognizable and Bailable.",
            "triggers_on": ["Doxxing & Impersonation"]
        },
        "US_CODE_2261A": {
            "jurisdiction": "United States (Federal)",
            "statute": "18 U.S. Code § 2261A (Interstate Stalking & Cyberstalking)",
            "statutory_text": (
                "Whoever with the intent to kill, injure, harass, intimidate, or place under surveillance with intent to kill, "
                "injure, harass, or intimidate another person, uses the mail, any interactive computer service or electronic "
                "communication service... or any other facility of interstate or foreign commerce, and causes reasonable fear of "
                "death or serious bodily injury, or causes substantial emotional distress."
            ),
            "penalties": "Federal prison sentence ranging from 5 years up to life imprisonment (if death results).",
            "bailable": "Federal magistrate discretion; high flight/danger risk.",
            "triggers_on": ["Threats & Intimidation", "Surveillance & Monitoring", "Persistent Pursuit", "Doxxing & Impersonation"]
        }
    }

    EVOLUTIONARY_MATRIX = [
        {
            "dimension": "Primary Delivery Vectors",
            "doj_1999_paradigm": "Usenet newsgroups, AOL chat rooms, basic dial-up email, bulletin board services (BBS).",
            "modern_2026_reality": "End-to-End encrypted messaging (Signal/WhatsApp), burner VOIP numbers, burner Instagram/TikTok accounts, AirTags/GPS trackers.",
            "forensic_challenge": "1999: ISP log retention was absent; 2026: End-to-end encryption and fast ephemeral wiping require device-level image preservation."
        },
        {
            "dimension": "Attribution & Anonymity",
            "doj_1999_paradigm": "Forged open SMTP relays and basic anonymous remailers (e.g., penet.fi).",
            "modern_2026_reality": "Multi-hop commercial VPNs, Tor onion routing, spoofed virtual SIMs, disposable email APIs.",
            "forensic_challenge": "Header inspection reveals intermediate proxies; requires subpoenaing ISP subscriber records and correlating gateway timestamps."
        },
        {
            "dimension": "Surveillance Mechanics",
            "doj_1999_paradigm": "Asking acquaintances in chat rooms, checking finger/whois databases, rudimentary web directories.",
            "modern_2026_reality": "Real-time automated geotag scrapers, spyware/stalkerware APKs, commercial data broker leaks, camera hacking.",
            "forensic_challenge": "High velocity tracking with micro-interval cadence, off-hours nocturnal surveillance patterns."
        },
        {
            "dimension": "Legal Recognition & Enforcement",
            "doj_1999_paradigm": "Fewer than one-third of US states had cyber-specific stalking statutes; law enforcement lacked digital forensic training.",
            "modern_2026_reality": "Comprehensive statutory coverage: BNS 78, IT Act 66E/67, 18 U.S.C. 2261A, ISO/IEC 27037 digital evidence standards.",
            "forensic_challenge": "Evidentiary chain-of-custody and SHA-256 cryptographic hashing required to avoid evidence suppression in criminal court."
        }
    ]

    @classmethod
    def match_incident(
        cls,
        detected_typologies: List[str],
        threat_score: float,
        off_hours_ratio: float = 0.0,
        burst_count: int = 0
    ) -> Dict[str, Any]:
        """
        Dynamically cross-references detected incident typologies with historical DOJ 1999 benchmarks
        and actionable modern legal statutes.
        """
        applicable_statutes = []

        for key, statute_info in cls.STATUTORY_DATABASE.items():
            common_triggers = set(statute_info["triggers_on"]).intersection(set(detected_typologies))
            if common_triggers:
                elements_satisfied = []
                for trigger in common_triggers:
                    if trigger == "Persistent Pursuit":
                        elements_satisfied.append("Repeated unwanted contact despite disinterest (BNS 78(1)(i) / 18 USC 2261A)")
                    elif trigger == "Surveillance & Monitoring":
                        elements_satisfied.append("Electronic monitoring of movements/internet communication (BNS 78(1)(ii) / 18 USC 2261A)")
                    elif trigger == "Threats & Intimidation":
                        elements_satisfied.append("Placing victim in reasonable fear of bodily harm or substantial distress (18 USC 2261A / IT Act 66E/67)")
                    elif trigger == "Doxxing & Impersonation":
                        elements_satisfied.append("Non-consensual disclosure of PII / privacy violation / deceptive impersonation (IT Act 66D, 66E)")

                applicable_statutes.append({
                    "code": key,
                    "statute_title": statute_info["statute"],
                    "jurisdiction": statute_info["jurisdiction"],
                    "penalties": statute_info["penalties"],
                    "matched_typologies": list(common_triggers),
                    "elements_satisfied": elements_satisfied,
                    "statutory_text": statute_info["statutory_text"]
                })

        # DOJ 1999 Corroboration points
        doj_corroborations = []
        if "Persistent Pursuit" in detected_typologies and off_hours_ratio >= 0.25:
            doj_corroborations.append("Obsessive nocturnal communication matches the 1999 DOJ pattern of unconstrained temporal boundaries.")
        if "Threats & Intimidation" in detected_typologies:
            doj_corroborations.append("Explicit threat escalation satisfies DOJ 1999 warning of digital threats preceding tangible offline stalking.")
        if "Doxxing & Impersonation" in detected_typologies:
            doj_corroborations.append("Targeted doxxing matches 1999 findings on third-party harassment solicitation (Dellapenta cyberstalking archetype).")
        if not doj_corroborations:
            doj_corroborations.append("Online stalking behaviors reflect baseline persistent digital harassment analyzed in DOJ 1999 Section II.")

        # Evidentiary recommendations
        preservation_recommendations = [
            "Formal Section 91 CrPC/BNSS or 18 U.S.C. § 2703(f) preservation letter served to intermediate ISPs and service providers.",
            "Cryptographic freeze of all original email raw headers with SHA-256 verification hash.",
            "Forensic extraction of mobile device message databases (SQLite .db files) using write-blocking software.",
            "Subpoena subscriber identity and connection logs for identified originating IP address."
        ]

        return {
            "doj_1999_reference": cls.DOJ_1999_REFERENCE,
            "applicable_statutes": applicable_statutes,
            "doj_corroborations": doj_corroborations,
            "preservation_recommendations": preservation_recommendations,
            "evolutionary_matrix": cls.EVOLUTIONARY_MATRIX
        }
