import re
from typing import Any, Dict, List, Set, Tuple


class StalkingDetector:
    """
    Offline Cyberstalking & Threat Detection Engine.
    Uses lexical keyword heuristics, regex pattern matching, and rule-based
    linguistic indicators to score threat intensity and map stalking typologies.
    """

    # Typology Lexicons
    PERSISTENT_PURSUIT_KEYWORDS = [
        "answer me", "pick up", "why are you ignoring", "stop ignoring", "respond",
        "reply to me", "unblock me", "made a new account", "why did you block",
        "talk to me", "can't escape", "won't let you go", "we need to talk",
        "don't shut me out", "listen to me", "you belong to me", "mine forever",
        "new number", "calling again", "check your dms", "can't run away",
        "pick up the phone", "why won't you answer", "you can't just pretend"
    ]

    THREATS_INTIMIDATION_KEYWORDS = [
        "kill", "murder", "hurt you", "destroy you", "ruin your life", "regret this",
        "watch your back", "pay for this", "make you suffer", "teach you a lesson",
        "slit", "bleed", "dead", "break your neck", "end your life", "die",
        "or else", "extort", "blackmail", "leak your photos", "expose you",
        "send your pictures", "send your video", "ruin your career", "take everything",
        "last chance", "face public exposure", "warning"
    ]

    SURVEILLANCE_MONITORING_KEYWORDS = [
        "saw you at", "saw you today", "outside your window", "outside your house",
        "parked outside", "watching you", "tracking you", "checked your location",
        "who was that guy", "who was that girl", "who were you with", "at your gym",
        "at your office", "at your college", "saw your car", "know where you live",
        "know your schedule", "saw your story", "saw you leave", "following you",
        "camera", "gps", "spy", "monitoring your phone", "saw what you wore",
        "bedroom light", "light is still on", "watching your window"
    ]

    DOXXING_IMPERSONATION_KEYWORDS = [
        "post your address", "leak your number", "call your boss", "email your manager",
        "send to your family", "tell your parents", "post on reddit", "post on twitter",
        "telegram channel", "doxx", "leak your ssn", "leak your phone",
        "made a profile of you", "pretending to be you", "fake account", "tell your workplace",
        "your employer", "your apartment number", "your zip code", "your aadhaar",
        "post on instagram", "have your phone number", "have your work email"
    ]

    # Regex patterns for identifying specific sensitive entities
    PATTERNS = {
        "phone_number": re.compile(
            r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
        ),
        "email_address": re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        ),
        "ip_address": re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ),
        "residential_keywords": re.compile(
            r"\b(?:apartment|apt|suite|ste|flat|street|st|avenue|ave|road|rd|blvd|terrace|lane|ln|drive|dr|pin code|zip)\b",
            re.IGNORECASE
        ),
        "urgent_urgency": re.compile(
            r"\b(?:now|immediately|hurry|asap|today|minutes|seconds|last chance|warning|right now)\b",
            re.IGNORECASE
        ),
        "profanity_aggression": re.compile(
            r"\b(?:bitch|slut|whore|bastard|idiot|loser|cunt|fuck|fucking|asshole|worthless)\b",
            re.IGNORECASE
        )
    }

    @classmethod
    def analyze_message(cls, text: str) -> Dict[str, Any]:
        """
        Evaluates a single message for threat markers, typologies, and extracted entities.
        """
        if not text or not text.strip():
            return {
                "threat_score": 0.0,
                "risk_tier": "LOW",
                "typologies": {},
                "matched_triggers": [],
                "entities_detected": {},
                "intensity_metrics": {"caps_ratio": 0.0, "exclamation_count": 0, "urgency_count": 0}
            }

        text_lower = text.lower()
        matched_pursuit = [kw for kw in cls.PERSISTENT_PURSUIT_KEYWORDS if kw in text_lower]
        matched_threats = [kw for kw in cls.THREATS_INTIMIDATION_KEYWORDS if kw in text_lower]
        matched_surveillance = [kw for kw in cls.SURVEILLANCE_MONITORING_KEYWORDS if kw in text_lower]
        matched_doxxing = [kw for kw in cls.DOXXING_IMPERSONATION_KEYWORDS if kw in text_lower]

        # Extract entities using regex
        detected_entities = {
            "phones": cls.PATTERNS["phone_number"].findall(text),
            "emails": cls.PATTERNS["email_address"].findall(text),
            "ips": cls.PATTERNS["ip_address"].findall(text),
            "residential_clues": cls.PATTERNS["residential_keywords"].findall(text)
        }

        # Calculate text emotional & urgency intensity
        letters_only = re.sub(r"[^A-Za-z]", "", text)
        caps_ratio = sum(1 for c in letters_only if c.isupper()) / max(len(letters_only), 1)
        exclamation_count = text.count("!") + text.count("?")
        urgency_matches = cls.PATTERNS["urgent_urgency"].findall(text)
        profanity_matches = cls.PATTERNS["profanity_aggression"].findall(text)

        # Typology individual scores (0 - 100)
        pursuit_score = min(100.0, len(matched_pursuit) * 35.0 + (15.0 if "unblock" in text_lower else 0.0))
        threat_score_cat = min(100.0, len(matched_threats) * 40.0 + (25.0 if any(k in text_lower for k in ["kill", "dead", "destroy", "ruin"]) else 0.0))
        surveillance_score = min(100.0, len(matched_surveillance) * 35.0 + (20.0 if any(k in text_lower for k in ["outside your", "parked outside", "window"]) else 0.0))
        
        doxxing_base = len(matched_doxxing) * 35.0
        if detected_entities["phones"]:
            doxxing_base += 25.0
        if detected_entities["residential_clues"]:
            doxxing_base += 25.0
        if detected_entities["emails"]:
            doxxing_base += 15.0
        doxxing_score = min(100.0, doxxing_base)

        typo_scores = [threat_score_cat, surveillance_score, doxxing_score, pursuit_score]
        max_typo = max(typo_scores)
        other_typos_sum = sum(typo_scores) - max_typo

        # Non-dilutive composite: Dominant typology sets the anchor, other typologies contribute
        composite = max_typo + (other_typos_sum * 0.15)

        # Intensity amplifiers
        if caps_ratio > 0.40 and len(letters_only) > 6:
            composite += 10.0
        if exclamation_count >= 2:
            composite += 5.0
        if urgency_matches:
            composite += min(12.0, len(urgency_matches) * 4.0)
        if profanity_matches:
            composite += min(15.0, len(profanity_matches) * 5.0)

        composite_score = round(min(100.0, max(0.0, composite)), 1)

        # Risk tier categorisation
        if composite_score >= 80.0:
            risk_tier = "CRITICAL"
        elif composite_score >= 60.0:
            risk_tier = "HIGH"
        elif composite_score >= 30.0:
            risk_tier = "ELEVATED"
        else:
            risk_tier = "LOW"

        all_triggers = sorted(list(set(
            matched_pursuit + matched_threats + matched_surveillance + matched_doxxing + profanity_matches
        )))

        return {
            "threat_score": composite_score,
            "risk_tier": risk_tier,
            "typologies": {
                "persistent_pursuit": {
                    "score": round(pursuit_score, 1),
                    "active": pursuit_score > 0,
                    "triggers": matched_pursuit
                },
                "threats_intimidation": {
                    "score": round(threat_score_cat, 1),
                    "active": threat_score_cat > 0,
                    "triggers": matched_threats
                },
                "surveillance_monitoring": {
                    "score": round(surveillance_score, 1),
                    "active": surveillance_score > 0,
                    "triggers": matched_surveillance
                },
                "doxxing_impersonation": {
                    "score": round(doxxing_score, 1),
                    "active": doxxing_score > 0,
                    "triggers": matched_doxxing
                }
            },
            "matched_triggers": all_triggers,
            "entities_detected": {k: v for k, v in detected_entities.items() if v},
            "intensity_metrics": {
                "caps_ratio": round(caps_ratio, 2),
                "exclamation_count": exclamation_count,
                "urgency_count": len(urgency_matches),
                "profanity_count": len(profanity_matches)
            }
        }

    @classmethod
    def analyze_stream(cls, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyzes a multi-message incident stream.
        Aggregates threat trajectory, peak threat, typology saturation, and active patterns.
        """
        if not messages:
            return {
                "aggregate_threat_score": 0.0,
                "risk_tier": "LOW",
                "message_count": 0,
                "typologies_detected": [],
                "typology_scores": {
                    "persistent_pursuit": 0.0,
                    "threats_intimidation": 0.0,
                    "surveillance_monitoring": 0.0,
                    "doxxing_impersonation": 0.0
                },
                "individual_evaluations": [],
                "cumulative_triggers": [],
                "high_risk_messages_count": 0
            }

        evaluations = []
        cumulative_triggers: Set[str] = set()
        
        pursuit_scores = []
        threat_scores = []
        surveillance_scores = []
        doxxing_scores = []
        total_threats = []

        for msg in messages:
            content = msg.get("content", "")
            eval_res = cls.analyze_message(content)
            evaluations.append({
                "message_id": msg.get("id"),
                "timestamp": msg.get("timestamp"),
                "sender": msg.get("sender"),
                "content": content,
                "evaluation": eval_res
            })
            total_threats.append(eval_res["threat_score"])
            pursuit_scores.append(eval_res["typologies"]["persistent_pursuit"]["score"])
            threat_scores.append(eval_res["typologies"]["threats_intimidation"]["score"])
            surveillance_scores.append(eval_res["typologies"]["surveillance_monitoring"]["score"])
            doxxing_scores.append(eval_res["typologies"]["doxxing_impersonation"]["score"])
            cumulative_triggers.update(eval_res["matched_triggers"])

        # Aggregate Typology Maximums & Saturations
        max_pursuit = max(pursuit_scores) if pursuit_scores else 0.0
        max_threats = max(threat_scores) if threat_scores else 0.0
        max_surveillance = max(surveillance_scores) if surveillance_scores else 0.0
        max_doxxing = max(doxxing_scores) if doxxing_scores else 0.0

        # Frequency factor for pursuit (repeated messages compound pursuit score)
        if len(messages) >= 4:
            max_pursuit = min(100.0, max_pursuit + min(35.0, (len(messages) - 3) * 6.0))

        # Peak threat is paramount in forensics; also factor in multi-typology saturation
        peak_threat = max(total_threats) if total_threats else 0.0
        
        # Count how many distinct typologies were activated
        active_typo_count = sum(1 for s in [max_pursuit, max_threats, max_surveillance, max_doxxing] if s >= 20.0)
        multi_typo_bonus = max(0, (active_typo_count - 1) * 5.0)

        top_3_threats = sorted(total_threats, reverse=True)[:3]
        top_avg = sum(top_3_threats) / len(top_3_threats) if top_3_threats else 0.0
        aggregate_threat = round(min(100.0, (peak_threat * 0.65) + (top_avg * 0.35) + multi_typo_bonus), 1)

        if aggregate_threat >= 80.0:
            risk_tier = "CRITICAL"
        elif aggregate_threat >= 60.0:
            risk_tier = "HIGH"
        elif aggregate_threat >= 30.0:
            risk_tier = "ELEVATED"
        else:
            risk_tier = "LOW"

        # Detect active typologies
        active_typologies = []
        if max_pursuit >= 20.0:
            active_typologies.append("Persistent Pursuit")
        if max_threats >= 20.0:
            active_typologies.append("Threats & Intimidation")
        if max_surveillance >= 20.0:
            active_typologies.append("Surveillance & Monitoring")
        if max_doxxing >= 20.0:
            active_typologies.append("Doxxing & Impersonation")

        high_risk_count = sum(1 for s in total_threats if s >= 60.0)

        return {
            "aggregate_threat_score": aggregate_threat,
            "risk_tier": risk_tier,
            "message_count": len(messages),
            "high_risk_messages_count": high_risk_count,
            "typologies_detected": active_typologies,
            "typology_scores": {
                "persistent_pursuit": round(max_pursuit, 1),
                "threats_intimidation": round(max_threats, 1),
                "surveillance_monitoring": round(max_surveillance, 1),
                "doxxing_impersonation": round(max_doxxing, 1)
            },
            "cumulative_triggers": sorted(list(cumulative_triggers)),
            "individual_evaluations": evaluations
        }
