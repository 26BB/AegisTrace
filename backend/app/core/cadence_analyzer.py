import statistics
from datetime import datetime, time
from typing import Any, Dict, List, Optional
from dateutil import parser


class CadenceAnalyzer:
    """
    Temporal & Behavioral Cadence Analysis Engine for Stalking Patterns.
    Computes message interval deltas, off-hours (nocturnal) transmission ratios,
    burst escalation frequencies, and velocity acceleration.
    """

    OFF_HOURS_START = time(23, 0)  # 11:00 PM
    OFF_HOURS_END = time(5, 0)     # 05:00 AM

    BURST_THRESHOLD_SECONDS = 300    # 5 minutes
    RAPID_THRESHOLD_SECONDS = 900    # 15 minutes

    @classmethod
    def is_off_hours(cls, dt: datetime) -> bool:
        """
        Determines if a timestamp falls within nocturnal off-hours (11 PM to 5 AM).
        """
        t = dt.time()
        if cls.OFF_HOURS_START <= t or t <= cls.OFF_HOURS_END:
            return True
        return False

    @classmethod
    def parse_datetime(cls, val: Any) -> Optional[datetime]:
        """
        Robustly parses various datetime formats or returns None if invalid.
        """
        if isinstance(val, datetime):
            return val
        if not val or not isinstance(val, str):
            return None
        try:
            return parser.parse(val)
        except Exception:
            return None

    @classmethod
    def analyze_cadence(cls, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Performs full chronological temporal cadence evaluation on a sequence of messages.
        """
        if not messages or len(messages) < 1:
            return {
                "message_count": 0,
                "off_hours_count": 0,
                "off_hours_ratio": 0.0,
                "intervals_seconds": [],
                "mean_interval_minutes": 0.0,
                "median_interval_minutes": 0.0,
                "min_interval_minutes": 0.0,
                "max_interval_minutes": 0.0,
                "std_dev_interval_minutes": 0.0,
                "burst_clusters_count": 0,
                "rapid_fire_count": 0,
                "acceleration_factor": 0.0,
                "escalation_detected": False,
                "temporal_risk_score": 0.0,
                "cadence_summary": "No messages provided for temporal analysis."
            }

        # Extract timestamps and sort chronologically
        timed_messages = []
        for idx, m in enumerate(messages):
            dt = cls.parse_datetime(m.get("timestamp"))
            if dt:
                timed_messages.append((dt, m, idx))

        if not timed_messages:
            return {
                "message_count": len(messages),
                "off_hours_count": 0,
                "off_hours_ratio": 0.0,
                "intervals_seconds": [],
                "mean_interval_minutes": 0.0,
                "median_interval_minutes": 0.0,
                "min_interval_minutes": 0.0,
                "max_interval_minutes": 0.0,
                "std_dev_interval_minutes": 0.0,
                "burst_clusters_count": 0,
                "rapid_fire_count": 0,
                "acceleration_factor": 0.0,
                "escalation_detected": False,
                "temporal_risk_score": 0.0,
                "cadence_summary": "Messages lacked valid timestamps for temporal cadence calculation."
            }

        # Sort chronologically by datetime
        timed_messages.sort(key=lambda x: x[0])

        total_msgs = len(timed_messages)
        off_hours_count = 0
        hourly_distribution: Dict[int, int] = {h: 0 for h in range(24)}

        for dt, _, _ in timed_messages:
            hourly_distribution[dt.hour] += 1
            if cls.is_off_hours(dt):
                off_hours_count += 1

        off_hours_ratio = round(off_hours_count / total_msgs, 3)

        # Calculate time delta intervals between consecutive messages
        intervals_seconds: List[float] = []
        burst_clusters = 0
        rapid_fires = 0

        for i in range(1, total_msgs):
            delta = (timed_messages[i][0] - timed_messages[i - 1][0]).total_seconds()
            # Ensure non-negative delta if slightly misordered or same second
            delta = max(0.0, delta)
            intervals_seconds.append(delta)
            
            if delta <= cls.BURST_THRESHOLD_SECONDS:
                burst_clusters += 1
            if delta <= cls.RAPID_THRESHOLD_SECONDS:
                rapid_fires += 1

        # Summary statistics
        if intervals_seconds:
            mean_sec = statistics.mean(intervals_seconds)
            median_sec = statistics.median(intervals_seconds)
            min_sec = min(intervals_seconds)
            max_sec = max(intervals_seconds)
            std_dev_sec = statistics.stdev(intervals_seconds) if len(intervals_seconds) > 1 else 0.0
        else:
            mean_sec = median_sec = min_sec = max_sec = std_dev_sec = 0.0

        # Acceleration Analysis: Compare first half of intervals vs second half of intervals
        # If second half has significantly shorter intervals, cadence is accelerating (escalation).
        acceleration_factor = 0.0
        escalation_detected = False
        if len(intervals_seconds) >= 4:
            half = len(intervals_seconds) // 2
            first_half_mean = statistics.mean(intervals_seconds[:half])
            second_half_mean = statistics.mean(intervals_seconds[half:])
            
            if first_half_mean > 0:
                # Ratio of speedup: e.g. 1.0 means same, > 1.0 means faster in second half
                acceleration_factor = round(first_half_mean / max(second_half_mean, 1.0), 2)
                if acceleration_factor >= 1.5 and second_half_mean < 7200:  # < 2 hours interval
                    escalation_detected = True

        # Temporal Risk Score calculation (0 to 100)
        # Factor 1: Off-hours ratio (up to 35 points)
        score_off_hours = min(35.0, off_hours_ratio * 50.0)
        # Factor 2: Burstiness (up to 35 points)
        burst_ratio = (burst_clusters / max(len(intervals_seconds), 1))
        score_burst = min(35.0, burst_ratio * 45.0 + min(15.0, burst_clusters * 3.0))
        # Factor 3: Acceleration / escalation (up to 30 points)
        score_accel = 0.0
        if escalation_detected:
            score_accel = min(30.0, 15.0 + (acceleration_factor * 5.0))
        elif acceleration_factor > 1.2:
            score_accel = 10.0

        temporal_risk_score = round(min(100.0, score_off_hours + score_burst + score_accel), 1)

        # Cadence Summary description
        summary_parts = []
        if off_hours_ratio >= 0.35:
            summary_parts.append(f"Severe nocturnal focus ({int(off_hours_ratio*100)}% during 11 PM - 5 AM off-hours)")
        elif off_hours_ratio > 0:
            summary_parts.append(f"{int(off_hours_ratio*100)}% nocturnal communication")

        if burst_clusters > 0:
            summary_parts.append(f"{burst_clusters} rapid message bursts (<5 min interval)")

        if escalation_detected:
            summary_parts.append(f"Pronounced transmission velocity acceleration ({acceleration_factor}x speed increase)")

        if not summary_parts:
            summary_parts.append("Normal cadence with no abnormal burst frequency or nocturnal concentration")

        cadence_summary = "; ".join(summary_parts) + "."

        return {
            "message_count": total_msgs,
            "off_hours_count": off_hours_count,
            "off_hours_ratio": off_hours_ratio,
            "hourly_distribution": hourly_distribution,
            "intervals_seconds": intervals_seconds,
            "mean_interval_minutes": round(mean_sec / 60.0, 1),
            "median_interval_minutes": round(median_sec / 60.0, 1),
            "min_interval_minutes": round(min_sec / 60.0, 1),
            "max_interval_minutes": round(max_sec / 60.0, 1),
            "std_dev_interval_minutes": round(std_dev_sec / 60.0, 1),
            "burst_clusters_count": burst_clusters,
            "rapid_fire_count": rapid_fires,
            "acceleration_factor": acceleration_factor,
            "escalation_detected": escalation_detected,
            "temporal_risk_score": temporal_risk_score,
            "cadence_summary": cadence_summary
        }
