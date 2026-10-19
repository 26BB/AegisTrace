import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import pandas as pd
import requests
import streamlit as st

# Direct core engine imports for autonomous standalone resilience
from backend.app.core.benchmark import LegalBenchmarkEngine
from backend.app.core.cadence_analyzer import CadenceAnalyzer
from backend.app.core.detector import StalkingDetector
from backend.app.core.evidence_vault import EvidenceVault
from backend.app.core.forensics_parser import ForensicHeaderParser
from backend.app.core.pdf_builder import ForensicPdfBuilder

# Backend API Configuration
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")


def check_backend_alive() -> bool:
    try:
        r = requests.get(f"{BACKEND_URL}/", timeout=1.2)
        return r.status_code == 200
    except Exception:
        return False


# =============================================================================
# STREAMLIT PAGE SETUP & CYBERSECURITY DARK UI THEMING
# =============================================================================
st.set_page_config(
    page_title="AegisTrace | Cyberstalking Forensic Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom High-Tech Dark Cyber CSS
st.markdown("""
<style>
    /* Dark Cyber Theme Variables */
    :root {
        --bg-main: #0b0f19;
        --card-bg: #111827;
        --card-border: #1f2937;
        --neon-cyan: #00f0ff;
        --neon-red: #ef4444;
        --neon-amber: #f59e0b;
        --neon-green: #10b981;
        --neon-purple: #a855f7;
        --text-dim: #94a3b8;
    }
    
    .stApp {
        background-color: #0b0f19;
        color: #f1f5f9;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
    }

    /* Metric cards */
    .metric-card {
        background: linear-gradient(145deg, #131c2e 0%, #0d1322 100%);
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 18px 20px;
        margin-bottom: 12px;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.4);
    }
    
    .metric-title {
        color: #94a3b8;
        font-size: 0.8rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }
    
    .metric-value {
        font-size: 1.85rem;
        font-weight: 800;
        margin-top: 4px;
        color: #f8fafc;
        letter-spacing: -0.02em;
    }
    
    .metric-sub {
        font-size: 0.78rem;
        color: #64748b;
        margin-top: 4px;
    }

    /* Risk Badges */
    .badge-critical {
        background: rgba(239, 68, 68, 0.15);
        color: #f87171;
        border: 1px solid #ef4444;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85rem;
        display: inline-block;
    }
    .badge-high {
        background: rgba(249, 115, 22, 0.15);
        color: #fb923c;
        border: 1px solid #f97316;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85rem;
        display: inline-block;
    }
    .badge-elevated {
        background: rgba(245, 158, 11, 0.15);
        color: #fbbf24;
        border: 1px solid #f59e0b;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85rem;
        display: inline-block;
    }
    .badge-low {
        background: rgba(16, 185, 129, 0.15);
        color: #34d399;
        border: 1px solid #10b981;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85rem;
        display: inline-block;
    }

    /* Typology pill */
    .typo-card {
        background-color: #111827;
        border: 1px solid #1f2937;
        border-radius: 8px;
        padding: 12px 14px;
        margin-bottom: 8px;
    }
    .typo-active {
        border-left: 4px solid #ef4444;
    }
    .typo-inactive {
        border-left: 4px solid #475569;
    }

    /* Monospace Hash Box */
    .hash-text {
        font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace;
        font-size: 0.76rem;
        color: #38bdf8;
        background: #090d16;
        padding: 4px 8px;
        border-radius: 4px;
        border: 1px solid #1e293b;
        word-break: break-all;
    }

    /* Code & Tables */
    .stDataFrame {
        border: 1px solid #1e293b;
        border-radius: 8px;
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)


# Load Sample Incident Dataset Helper
def get_sample_data() -> Dict[str, Any]:
    sample_path = os.path.join(os.path.dirname(__file__), "data", "sample_incident.json")
    if os.path.exists(sample_path):
        try:
            with open(sample_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    # Fallback inline sample
    return {
        "incident_metadata": {
            "case_number": "AEGIS-2026-STK-0924",
            "title": "Cross-Platform Targeted Stalking & Nocturnal Intimidation Incident",
            "victim_alias": "Victim-JaneDoe",
            "suspect_alias": "ObsessiveGhost_99",
            "platform": "SMS / Instagram DM / Anonymous SMTP"
        },
        "messages": [
            {"sender": "ObsessiveGhost_99", "timestamp": "2026-10-12T14:20:00Z", "content": "Hey Jane, why did you block my account? We really need to talk."},
            {"sender": "ObsessiveGhost_99", "timestamp": "2026-10-12T23:35:00Z", "content": "I saw you at your gym today wearing that blue jacket. Who was that guy?"},
            {"sender": "ObsessiveGhost_99", "timestamp": "2026-10-13T01:15:00Z", "content": "I see your apartment bedroom light is still on. You can't hide from me."},
            {"sender": "ObsessiveGhost_99", "timestamp": "2026-10-13T02:40:00Z", "content": "I know where you live: 742 Evergreen Terrace. Parked outside watching your window."},
            {"sender": "ObsessiveGhost_99", "timestamp": "2026-10-13T02:45:00Z", "content": "I will destroy you and leak your private photos unless you reply now. Watch your back."}
        ],
        "raw_email_headers": "Delivered-To: jane.doe@corporate-secure.org\nReceived: from relay02.anonymizer-proxy.net [198.51.100.88] by mx.google.com;\nReceived-SPF: softfail\nDate: Tue, 13 Oct 2026 05:45:50 -0400\nFrom: <alert@anonymous-mail.cc>\nSubject: FINAL WARNING\nX-Originating-IP: [203.0.113.194]\nUser-Agent: Mozilla/5.0 Thunderbird"
    }


# Initialize Session State
if "messages_input" not in st.session_state:
    sample = get_sample_data()
    st.session_state.messages_input = sample["messages"]
    st.session_state.sample_headers = sample["raw_email_headers"]
    st.session_state.case_metadata = sample["incident_metadata"]
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = None
if "forensic_trace_results" not in st.session_state:
    st.session_state.forensic_trace_results = None


# =============================================================================
# SIDEBAR CONTROLS & SYSTEM TELEMETRY
# =============================================================================
with st.sidebar:
    st.markdown("### 🛡️ **AEGISTRACE**")
    st.caption("Forensic Cyberstalking Incident Engine")
    st.markdown("---")

    backend_online = check_backend_alive()
    if backend_online:
        st.success("🟢 FastAPI Backend: Online (Port 8000)")
    else:
        st.info("🔵 Standalone Mode: Direct Core Engine")

    st.markdown("#### 📁 Case Metadata")
    case_num = st.text_input("Case Reference", value=st.session_state.case_metadata.get("case_number", "AEGIS-2026-001"))
    case_title = st.text_input("Incident Title", value=st.session_state.case_metadata.get("title", "Targeted Stalking Stream"))
    victim_name = st.text_input("Victim Identifier", value=st.session_state.case_metadata.get("victim_alias", "Victim-JaneDoe"))
    suspect_name = st.text_input("Suspect Identifier", value=st.session_state.case_metadata.get("suspect_alias", "Suspect-Unknown"))
    platform = st.text_input("Vectors / Platform", value=st.session_state.case_metadata.get("platform", "SMS / Direct Message / SMTP"))

    st.markdown("---")
    col_sb1, col_sb2 = st.columns(2)
    with col_sb1:
        if st.button("🔄 Sample Data", use_container_width=True, help="Load realistic demonstration case scenario"):
            sample = get_sample_data()
            st.session_state.messages_input = sample["messages"]
            st.session_state.sample_headers = sample["raw_email_headers"]
            st.session_state.case_metadata = sample["incident_metadata"]
            st.session_state.analysis_results = None
            st.session_state.forensic_trace_results = None
            st.rerun()
    with col_sb2:
        if st.button("🆕 Blank Case", use_container_width=True, help="Wipe all data to start a live custom investigation"):
            st.session_state.messages_input = []
            st.session_state.sample_headers = ""
            st.session_state.case_metadata = {
                "case_number": "AEGIS-LIVE-DEMO",
                "title": "Live Faculty Incident Examination",
                "victim_alias": "Victim-Live",
                "suspect_alias": "Suspect-Unknown",
                "platform": "Multi-Platform Direct Messages"
            }
            st.session_state.analysis_results = None
            st.session_state.forensic_trace_results = None
            st.rerun()

    st.markdown("---")
    st.markdown(
        "<div style='font-size:0.75rem; color:#64748b; line-height:1.4;'>"
        "<b>Evidentiary Compliance:</b><br/>"
        "• RFC 822 / 5322 Routing Forensics<br/>"
        "• ISO/IEC 27037 Digital Custody<br/>"
        "• SHA-256 Digest Verification<br/>"
        "• 1999 DOJ Cyberstalking Benchmark"
        "</div>",
        unsafe_allow_html=True
    )


# =============================================================================
# TOP NAVIGATION TABS
# =============================================================================
tab_analyze, tab_headers, tab_benchmark = st.tabs([
    "📊 1. Analyze Incident",
    "🔍 2. Forensic Header Trace",
    "⚖️ 3. DOJ 1999 vs Modern Benchmark & Dossier"
])


# =============================================================================
# TAB 1: ANALYZE INCIDENT
# =============================================================================
with tab_analyze:
    st.markdown("### Cyberstalking Incident Evaluation & Temporal Escalation")
    st.caption("Upload your own custom evidence dataset, paste/type records live, or analyze persistent pursuit, surveillance, doxxing, and nocturnal velocity.")

    col_input, col_meta = st.columns([3, 1])

    with col_input:
        st.markdown("##### 📂 Ingest Custom Evidence or Edit Live Stream")

        up_col1, up_col2 = st.columns([2, 1])
        with up_col1:
            uploaded_file = st.file_uploader(
                "Upload Custom Evidence (CSV or JSON)",
                type=["csv", "json"],
                help="Upload a CSV with columns (sender, timestamp, content) or an AegisTrace incident JSON",
                key="evidence_uploader"
            )
        with up_col2:
            template_csv = "sender,timestamp,content\nSuspect_Alpha,2026-10-19T23:15:00Z,Why did you block me? Answer now.\nSuspect_Alpha,2026-10-20T01:30:00Z,I saw you leaving your building today.\nSuspect_Alpha,2026-10-20T02:00:00Z,I know where you live. Reply or I will leak your photos.\n"
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            st.download_button(
                "📥 Download CSV Template",
                data=template_csv,
                file_name="evidence_template.csv",
                mime="text/csv",
                use_container_width=True
            )

        if uploaded_file is not None:
            try:
                if uploaded_file.name.endswith(".csv"):
                    df_up = pd.read_csv(uploaded_file)
                    df_up.columns = [c.lower().strip() for c in df_up.columns]
                    if "content" in df_up.columns:
                        if "sender" not in df_up.columns:
                            df_up["sender"] = "Suspect"
                        if "timestamp" not in df_up.columns:
                            df_up["timestamp"] = datetime.now(timezone.utc).isoformat()
                        st.session_state.messages_input = df_up[["sender", "timestamp", "content"]].to_dict(orient="records")
                        st.session_state.analysis_results = None
                        st.success(f"✅ Ingested {len(df_up)} records from custom CSV file!")
                    else:
                        st.error("Uploaded CSV must contain at least a 'content' column.")
                elif uploaded_file.name.endswith(".json"):
                    c_json = json.load(uploaded_file)
                    if isinstance(c_json, list):
                        st.session_state.messages_input = c_json
                    elif isinstance(c_json, dict) and "messages" in c_json:
                        st.session_state.messages_input = c_json["messages"]
                        if "incident_metadata" in c_json:
                            st.session_state.case_metadata = c_json["incident_metadata"]
                        if "raw_email_headers" in c_json:
                            st.session_state.sample_headers = c_json["raw_email_headers"]
                    st.session_state.analysis_results = None
                    st.success("✅ Ingested custom evidence JSON dataset!")
            except Exception as ex:
                st.error(f"Error parsing uploaded file: {ex}")

        # Format messages into editable DataFrame
        if st.session_state.messages_input:
            df_msgs = pd.DataFrame(st.session_state.messages_input)
            for expected_col in ["sender", "timestamp", "content"]:
                if expected_col not in df_msgs.columns:
                    df_msgs[expected_col] = ""
            df_msgs = df_msgs[["sender", "timestamp", "content"]]
        else:
            df_msgs = pd.DataFrame(columns=["sender", "timestamp", "content"])

        st.caption("💡 *Edit text directly in cells below, or click the **'+'** icon at the bottom of the table to add new messages live during your demo.*")
        edited_df = st.data_editor(
            df_msgs,
            column_config={
                "sender": st.column_config.TextColumn("Sender Handle", width="medium"),
                "timestamp": st.column_config.TextColumn("Timestamp (UTC / ISO)", width="medium"),
                "content": st.column_config.TextColumn("Message Content", width="large")
            },
            num_rows="dynamic",
            use_container_width=True,
            key="message_editor"
        )

    with col_meta:
        st.markdown("##### Quick Actions")
        msg_count = len(edited_df) if edited_df is not None else 0
        st.write(f"**Total Ingested Messages:** {msg_count}")
        run_analysis = st.button("⚡ Run Threat & Cadence Analysis", type="primary", use_container_width=True)

        if st.button("🗑️ Clear Message Table", use_container_width=True):
            st.session_state.messages_input = []
            st.session_state.analysis_results = None
            st.rerun()

        st.markdown("---")
        st.markdown(
            "<div style='font-size:0.8rem; color:#94a3b8;'>"
            "Algorithm evaluates:<br/>"
            "• Lexical threat scoring (0-100)<br/>"
            "• Typology saturation mapping<br/>"
            "• Nocturnal cadence ratio (11 PM - 5 AM)<br/>"
            "• Time interval delta collapse<br/>"
            "• Cryptographic SHA-256 seal"
            "</div>",
            unsafe_allow_html=True
        )

    # Perform Analysis
    if run_analysis or (st.session_state.analysis_results is None and len(edited_df) > 0):
        messages_list = edited_df.to_dict(orient="records") if edited_df is not None else []
        if len(messages_list) == 0:
            st.warning("⚠️ No messages to analyze. Please add rows or upload an evidence file.")
        else:
            st.session_state.messages_input = messages_list

        # Execute Core Analysis (Direct Core or API)
        with st.spinner("Processing lexical heuristics, temporal cadence, and cryptographic evidence hashing..."):
            detection = StalkingDetector.analyze_stream(messages_list)
            cadence = CadenceAnalyzer.analyze_cadence(messages_list)

            # Composite Score (75% linguistic, 25% cadence risk)
            comp_score = round(min(100.0, (detection["aggregate_threat_score"] * 0.75) + (cadence["temporal_risk_score"] * 0.25)), 1)
            if comp_score >= 80:
                tier = "CRITICAL"
            elif comp_score >= 60:
                tier = "HIGH"
            elif comp_score >= 30:
                tier = "ELEVATED"
            else:
                tier = "LOW"

            # Evidence Ledger with SHA-256
            evidence_ledger = []
            for idx, msg in enumerate(messages_list, 1):
                rec = EvidenceVault.generate_custody_record(
                    item_id=f"EV-MSG-{idx:03d}",
                    item_type="MESSAGE_CONTENT",
                    content=msg.get("content", ""),
                    source_identifier=f"{msg.get('sender', 'Suspect')} @ {msg.get('timestamp', 'Unknown')}"
                )
                evidence_ledger.append(rec)

            legal_bench = LegalBenchmarkEngine.match_incident(
                detected_typologies=detection["typologies_detected"],
                threat_score=comp_score,
                off_hours_ratio=cadence["off_hours_ratio"],
                burst_count=cadence["burst_clusters_count"]
            )

            dossier_hash = EvidenceVault.calculate_sha256({
                "case": case_num,
                "score": comp_score,
                "ledger": evidence_ledger
            })

            st.session_state.analysis_results = {
                "aggregate_threat_score": comp_score,
                "risk_tier": tier,
                "linguistic_score": detection["aggregate_threat_score"],
                "temporal_score": cadence["temporal_risk_score"],
                "typologies_detected": detection["typologies_detected"],
                "typology_scores": detection["typology_scores"],
                "cumulative_triggers": detection["cumulative_triggers"],
                "cadence_metrics": cadence,
                "evidence_ledger": evidence_ledger,
                "individual_evaluations": detection["individual_evaluations"],
                "legal_benchmark": legal_bench,
                "dossier_hash": dossier_hash
            }

    # Display Analysis Dashboard
    if st.session_state.analysis_results:
        res = st.session_state.analysis_results
        cad = res["cadence_metrics"]

        st.markdown("---")

        # Top Executive Metric Cards
        mcol1, mcol2, mcol3, mcol4 = st.columns(4)

        tier_class = f"badge-{res['risk_tier'].lower()}"

        with mcol1:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-title">Composite Threat Level</div>
                    <div class="metric-value">{res['aggregate_threat_score']} <span style="font-size:1rem;color:#64748b;">/ 100</span></div>
                    <div class="metric-sub"><span class="{tier_class}">{res['risk_tier']} RISK</span></div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with mcol2:
            off_pct = int(cad['off_hours_ratio'] * 100)
            off_badge = "badge-critical" if off_pct >= 40 else ("badge-elevated" if off_pct > 0 else "badge-low")
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-title">Off-Hours Concentration</div>
                    <div class="metric-value">{off_pct}%</div>
                    <div class="metric-sub"><span class="{off_badge}">{cad['off_hours_count']} of {cad['message_count']} (11PM - 5AM)</span></div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with mcol3:
            burst_badge = "badge-critical" if cad['burst_clusters_count'] >= 2 else "badge-low"
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-title">Velocity Burst Clusters</div>
                    <div class="metric-value">{cad['burst_clusters_count']}</div>
                    <div class="metric-sub"><span class="{burst_badge}">Deltas &lt; 5 minutes</span></div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with mcol4:
            acc_val = f"{cad['acceleration_factor']}x" if cad['acceleration_factor'] > 0 else "Baseline"
            acc_badge = "badge-high" if cad.get("escalation_detected") else "badge-low"
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-title">Cadence Acceleration</div>
                    <div class="metric-value">{acc_val}</div>
                    <div class="metric-sub"><span class="{acc_badge}">{'VELOCITY COLLAPSE' if cad.get('escalation_detected') else 'STABLE CADENCE'}</span></div>
                </div>
                """,
                unsafe_allow_html=True
            )

        # Typology Saturation Cards & Triggers
        st.markdown("#### 🎯 Detected Cyberstalking Typologies")
        tcol1, tcol2, tcol3, tcol4 = st.columns(4)

        t_scores = res["typology_scores"]

        def render_typo_box(name: str, score: float, description: str):
            is_act = score >= 20.0
            border_cls = "typo-active" if is_act else "typo-inactive"
            badge = "<span class='badge-critical'>ACTIVE</span>" if is_act else "<span class='badge-low'>DORMANT</span>"
            return f"""
            <div class="typo-card {border_cls}">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <b style="color:#f8fafc; font-size:0.9rem;">{name}</b>
                    {badge}
                </div>
                <div style="font-size:1.4rem; font-weight:700; margin: 4px 0; color:#38bdf8;">
                    {score} <span style="font-size:0.75rem; color:#64748b;">/ 100</span>
                </div>
                <div style="font-size:0.75rem; color:#94a3b8; line-height:1.3;">
                    {description}
                </div>
            </div>
            """

        with tcol1:
            st.markdown(render_typo_box("Persistent Pursuit", t_scores["persistent_pursuit"], "Repetitive outreach, bypassing blocks, multiple handles."), unsafe_allow_html=True)
        with tcol2:
            st.markdown(render_typo_box("Threats & Intimidation", t_scores["threats_intimidation"], "Harm threats, coercion, blackmail, destruction."), unsafe_allow_html=True)
        with tcol3:
            st.markdown(render_typo_box("Surveillance & Monitoring", t_scores["surveillance_monitoring"], "Physical/digital presence, location tracking, schedule observation."), unsafe_allow_html=True)
        with tcol4:
            st.markdown(render_typo_box("Doxxing & Impersonation", t_scores["doxxing_impersonation"], "Leaking phone/address/workplace, unauthorized exposure."), unsafe_allow_html=True)

        # Active Keywords Triggered
        if res["cumulative_triggers"]:
            st.markdown("##### 🔑 Linguistic & Threat Triggers Detected")
            pill_html = " ".join([f"<span class='hash-text' style='color:#f87171; border-color:#ef4444;'>{kw}</span>" for kw in res["cumulative_triggers"]])
            st.markdown(pill_html, unsafe_allow_html=True)

        st.markdown("---")

        # Escalation Timeline & Visual Charts
        st.markdown("#### 📈 Threat Escalation & Temporal Velocity Trajectory")
        
        # Build timeline dataframe
        timeline_rows = []
        for idx, item in enumerate(res["individual_evaluations"], 1):
            ts = item.get("timestamp")
            dt = CadenceAnalyzer.parse_datetime(ts)
            timeline_rows.append({
                "Seq": idx,
                "Timestamp": dt if dt else f"Msg #{idx}",
                "Threat Score": item["evaluation"]["threat_score"],
                "Pursuit": item["evaluation"]["typologies"]["persistent_pursuit"]["score"],
                "Threats": item["evaluation"]["typologies"]["threats_intimidation"]["score"],
                "Surveillance": item["evaluation"]["typologies"]["surveillance_monitoring"]["score"],
                "Doxxing": item["evaluation"]["typologies"]["doxxing_impersonation"]["score"],
                "Sender": item.get("sender"),
                "Content": item.get("content")
            })

        df_timeline = pd.DataFrame(timeline_rows)
        if not df_timeline.empty and "Timestamp" in df_timeline:
            st.line_chart(
                df_timeline,
                x="Seq",
                y=["Threat Score", "Threats", "Surveillance", "Doxxing", "Pursuit"],
                color=["#ef4444", "#dc2626", "#f59e0b", "#a855f7", "#38bdf8"],
                use_container_width=True
            )

        st.markdown("---")

        # Cryptographic Evidence Ledger
        st.markdown("#### 🔒 Cryptographic Evidence Ledger (ISO/IEC 27037)")
        st.caption("Each message is sealed with a SHA-256 cryptographic digest at intake to ensure chain-of-custody integrity.")

        ledger_df = pd.DataFrame([
            {
                "Evidence ID": e["evidence_id"],
                "Type": e["item_type"],
                "Source": e["source"],
                "Content Snippet": e["preview"],
                "SHA-256 Checksum": e["sha256_hash"],
                "Integrity Status": "✅ VERIFIED INTACT"
            }
            for e in res["evidence_ledger"]
        ])
        st.dataframe(ledger_df, use_container_width=True, hide_index=True)


# =============================================================================
# TAB 2: FORENSIC HEADER TRACE
# =============================================================================
with tab_headers:
    st.markdown("### RFC 822 Email Header Routing & Originating IP Forensics")
    st.caption("Inspect raw mail transfer agent (MTA) headers, uncover intermediate relay hops, strip private bogons, and isolate true originating public IPs.")

    col_h_input, col_h_actions = st.columns([3, 1])

    with col_h_input:
        header_text = st.text_area(
            "Paste Raw RFC 822 / 5322 Email Headers",
            value=st.session_state.sample_headers,
            height=240,
            key="raw_headers_input"
        )

    with col_h_actions:
        st.markdown("##### Header Diagnostics")
        btn_trace = st.button("🔎 Trace Server Hops & Public IP", type="primary", use_container_width=True)
        if st.button("📋 Load Sample Header", use_container_width=True):
            sample = get_sample_data()
            st.session_state.sample_headers = sample["raw_email_headers"]
            st.session_state.forensic_trace_results = None
            st.rerun()

        if st.button("🗑️ Clear Headers", use_container_width=True):
            st.session_state.sample_headers = ""
            st.session_state.forensic_trace_results = None
            st.rerun()

        up_hdr = st.file_uploader("📂 Ingest Header File (.eml / .txt)", type=["eml", "txt"], key="hdr_uploader")
        if up_hdr is not None:
            try:
                hdr_bytes = up_hdr.read()
                st.session_state.sample_headers = hdr_bytes.decode("utf-8", errors="replace")
                st.session_state.forensic_trace_results = None
                st.success("✅ Header file loaded!")
            except Exception as ex:
                st.error(f"Error loading header file: {ex}")

        st.markdown(
            "<div style='font-size:0.78rem; color:#94a3b8; margin-top:8px;'>"
            "• Chronological hop unwinding<br/>"
            "• RFC 1918 Private IP filtering<br/>"
            "• SPF / DKIM verification<br/>"
            "• Client User-Agent fingerprinting"
            "</div>",
            unsafe_allow_html=True
        )

    # Process Headers
    if btn_trace or (st.session_state.forensic_trace_results is None and header_text.strip()):
        if header_text.strip():
            with st.spinner("Parsing RFC 822 headers and mapping relay sequence..."):
                parsed = ForensicHeaderParser.parse_headers(header_text)
                hdr_hash = EvidenceVault.calculate_sha256(header_text)
                parsed["sha256_hash"] = hdr_hash
                st.session_state.forensic_trace_results = parsed

    # Display Header Trace Findings
    if st.session_state.forensic_trace_results:
        trace = st.session_state.forensic_trace_results

        st.markdown("---")
        hcol1, hcol2, hcol3, hcol4 = st.columns(4)

        with hcol1:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-title">Originating Public IP</div>
                    <div class="metric-value" style="color:#00f0ff; font-family:monospace; font-size:1.35rem;">
                        {trace.get('originating_public_ip', 'Hidden')}
                    </div>
                    <div class="metric-sub">Closest Public Ingress Node</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with hcol2:
            spf_val = trace.get("authentication", {}).get("spf_status", "Unknown")
            spf_class = "badge-low" if spf_val == "PASS" else ("badge-critical" if "FAIL" in spf_val else "badge-elevated")
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-title">SPF Alignment</div>
                    <div class="metric-value"><span class="{spf_class}">{spf_val}</span></div>
                    <div class="metric-sub">Sender Policy Framework</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with hcol3:
            dkim_val = trace.get("authentication", {}).get("dkim_status", "None")
            dkim_class = "badge-low" if dkim_val == "PASS" else ("badge-critical" if "FAIL" in dkim_val else "badge-elevated")
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-title">DKIM Signature</div>
                    <div class="metric-value"><span class="{dkim_class}">{dkim_val}</span></div>
                    <div class="metric-sub">Cryptographic Integrity</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with hcol4:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-title">Relay Hop Depth</div>
                    <div class="metric-value">{trace.get('hop_count', 0)}</div>
                    <div class="metric-sub">MTA Chain Traversals</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        # Basic metadata
        st.markdown("##### ✉️ Extracted Envelope Details")
        env_col1, env_col2 = st.columns(2)
        with env_col1:
            st.write(f"**Subject:** `{trace.get('subject')}`")
            st.write(f"**From:** `{trace.get('from')}`")
            st.write(f"**To:** `{trace.get('to')}`")
        with env_col2:
            st.write(f"**Date:** `{trace.get('date')}`")
            st.write(f"**Message-ID:** `{trace.get('message_id')}`")
            st.write(f"**Client User-Agent / Mailer:** `{trace.get('user_agent')}`")

        # Header SHA-256 Evidence Seal
        st.markdown(
            f"**Header SHA-256 Digest:** <span class='hash-text'>{trace.get('sha256_hash')}</span>",
            unsafe_allow_html=True
        )

        if trace.get("anomalies"):
            st.markdown("##### ⚠️ Forensic Anomalies Detected")
            for a in trace["anomalies"]:
                st.warning(f"• {a}")

        # Routing Hop Sequence Table
        st.markdown("##### 🌐 Chronological Relay Hop Sequence (Sender to Destination)")
        if trace.get("hops"):
            hop_table_data = []
            for h in trace["hops"]:
                hop_table_data.append({
                    "Hop #": h["hop_index"],
                    "Sending Host (From)": h["from_host"],
                    "Receiving Host (By)": h["by_host"],
                    "Extracted IP": h["identified_ip"],
                    "IP Classification": "PUBLIC INTERNET" if h["is_public_hop"] else "PRIVATE RFC 1918 / RELAY",
                    "Protocol": h["protocol"],
                    "Timestamp": h["timestamp_str"]
                })
            st.dataframe(pd.DataFrame(hop_table_data), use_container_width=True, hide_index=True)


# =============================================================================
# TAB 3: DOJ 1999 VS MODERN BENCHMARK & OFFICIAL PDF DOSSIER
# =============================================================================
with tab_benchmark:
    st.markdown("### Comparative Jurisprudence: 1999 DOJ Report vs Modern Frameworks")
    st.caption("Benchmark detected behaviors against the landmark 1999 US DOJ Cyberstalking Report, Indian Criminal Code (BNS 78, IT Act 66E/67), and US Federal Law (18 U.S.C. § 2261A).")

    # Comparative Evolutionary Matrix
    st.markdown("#### 🏛️ Evolution of Cyberstalking (1999 vs 2026)")
    evo_matrix = LegalBenchmarkEngine.EVOLUTIONARY_MATRIX
    evo_df = pd.DataFrame(evo_matrix)
    st.dataframe(
        evo_df,
        column_config={
            "dimension": st.column_config.TextColumn("Tactical Dimension", width="small"),
            "doj_1999_paradigm": st.column_config.TextColumn("1999 DOJ Report Paradigm", width="medium"),
            "modern_2026_reality": st.column_config.TextColumn("Modern 2026 Reality", width="medium"),
            "forensic_challenge": st.column_config.TextColumn("Evidentiary & Legal Challenge", width="large"),
        },
        use_container_width=True,
        hide_index=True
    )

    st.markdown("---")

    # Statutory Mapping based on active analysis
    st.markdown("#### ⚖️ Applicable Criminal Statutes & Elements Satisfied")
    current_analysis = st.session_state.analysis_results
    if current_analysis:
        matched_statutes = current_analysis.get("legal_benchmark", {}).get("applicable_statutes", [])
        if matched_statutes:
            for st_item in matched_statutes:
                with st.expander(f"📌 {st_item['statute_title']} ({st_item['jurisdiction']})", expanded=True):
                    sc1, sc2 = st.columns([2, 1])
                    with sc1:
                        st.markdown(f"**Statutory Definition:**<br/>*{st_item['statutory_text']}*", unsafe_allow_html=True)
                        st.markdown("**Elements of Crime Satisfied in this Incident:**")
                        for el in st_item["elements_satisfied"]:
                            st.markdown(f"• <span style='color:#34d399;'>{el}</span>", unsafe_allow_html=True)
                    with sc2:
                        st.markdown(
                            f"""
                            <div class="metric-card" style="margin-top:0;">
                                <div class="metric-title">Statutory Penalty</div>
                                <div style="font-size:0.95rem; font-weight:700; color:#fbbf24; margin-top:6px;">
                                    {st_item['penalties']}
                                </div>
                                <div class="metric-sub">Triggered by: {', '.join(st_item['matched_typologies'])}</div>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )
        else:
            st.info("No active high-severity criminal typologies met statutory threshold.")

        # Preservation recommendations
        st.markdown("##### 🛡️ Evidentiary Preservation & Legal Next Steps")
        recs = current_analysis.get("legal_benchmark", {}).get("preservation_recommendations", [])
        for r in recs:
            st.markdown(f"• **{r}**")

    else:
        st.info("Run threat analysis in Tab 1 to dynamically cross-reference detected incident typologies with applicable statutes.")

    st.markdown("---")

    # PDF Dossier Generation Section
    st.markdown("#### 📄 Official Court-Admissible Forensic Incident Dossier (PDF)")
    st.write(
        "Compile a comprehensive, publication-grade multi-page forensic incident dossier including "
        "executive risk assessments, typology breakdowns, temporal cadence analysis, "
        "RFC 822 routing hops, statutory benchmark mapping, and ISO/IEC 27037 SHA-256 evidence chain of custody."
    )

    if current_analysis:
        incident_meta = {
            "case_number": case_num,
            "title": case_title,
            "victim_alias": victim_name,
            "suspect_alias": suspect_name,
            "platform": platform
        }

        # Generate PDF bytes directly
        pdf_bytes = ForensicPdfBuilder.generate_dossier(
            incident_data=incident_meta,
            analysis_data=current_analysis,
            forensic_trace=st.session_state.forensic_trace_results,
            legal_benchmark=current_analysis.get("legal_benchmark")
        )

        pdf_filename = f"AegisTrace-Dossier-{case_num}.pdf"

        pcol1, pcol2 = st.columns([1, 2])
        with pcol1:
            st.download_button(
                label="📥 Download Forensic Dossier (PDF)",
                data=pdf_bytes,
                file_name=pdf_filename,
                mime="application/pdf",
                type="primary",
                use_container_width=True
            )
        with pcol2:
            st.markdown(
                f"<div style='font-size:0.85rem; color:#94a3b8; padding-top:8px;'>"
                f"Generated {len(pdf_bytes):,} bytes | Case: <b>{case_num}</b> | "
                f"Audit Hash: <span class='hash-text'>{current_analysis.get('dossier_hash')[:24]}...</span>"
                f"</div>",
                unsafe_allow_html=True
            )
    else:
        st.warning("Please run an incident analysis in Tab 1 before downloading the PDF dossier.")
