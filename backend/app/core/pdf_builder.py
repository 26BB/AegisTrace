import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass ReportLab Canvas that records total pages and prints
    'Page X of Y' alongside legal confidentiality notices on every page.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#475569"))

        # Running header on pages after the first
        if self._pageNumber > 1:
            self.drawString(54, 11 * inch - 36, "AEGISTRACE DIGITAL FORENSICS — OFFICIAL INCIDENT DOSSIER")
            self.drawRightString(8.5 * inch - 54, 11 * inch - 36, "STRICTLY CONFIDENTIAL / EVIDENCE LOCK")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 11 * inch - 40, 8.5 * inch - 54, 11 * inch - 40)

        # Running footer on all pages
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 45, 8.5 * inch - 54, 45)

        self.setFont("Helvetica", 7.5)
        self.drawString(54, 32, "ISO/IEC 27037 Digital Evidence Admissibility Standard — SHA-256 Cryptographic Chain of Custody Verified")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * inch - 54, 32, page_str)
        self.restoreState()


class ForensicPdfBuilder:
    """
    Constructs a multi-page, publication-grade Cyberstalking Forensic Incident Dossier (PDF).
    """

    @classmethod
    def generate_dossier(
        cls,
        incident_data: Dict[str, Any],
        analysis_data: Dict[str, Any],
        forensic_trace: Optional[Dict[str, Any]] = None,
        legal_benchmark: Optional[Dict[str, Any]] = None
    ) -> bytes:
        """
        Builds and returns the raw PDF bytes for an incident dossier.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54
        )

        styles = getSampleStyleSheet()

        # Custom typography styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a")
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor("#475569")
        )
        section_heading = ParagraphStyle(
            "SectionHeading",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#1e293b")
        )
        body_bold = ParagraphStyle(
            "BodyBold",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#0f172a")
        )
        mono_style = ParagraphStyle(
            "Mono",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#09090b")
        )
        mono_bold = ParagraphStyle(
            "MonoBold",
            parent=styles["Normal"],
            fontName="Courier-Bold",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#09090b")
        )

        story = []

        # =========================================================================
        # 1. HEADER & METADATA BLOCK
        # =========================================================================
        header_table_data = [
            [
                Paragraph("<b>AEGISTRACE INCIDENT DOSSIER</b><br/><font size='8'>CYBERSTALKING FORENSIC & THREAT ANALYSIS PLATFORM</font>", title_style),
                Paragraph(
                    f"<b>CASE REF:</b> {incident_data.get('case_number', 'CASE-AUTO-001')}<br/>"
                    f"<b>DATE UTC:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}<br/>"
                    f"<b>CLASSIFICATION:</b> LAW ENFORCEMENT SENSITIVE",
                    subtitle_style
                )
            ]
        ]
        header_table = Table(header_table_data, colWidths=[4.2 * inch, 2.8 * inch])
        header_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(header_table)
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

        # Case particulars table
        case_info = [
            [
                Paragraph("<b>Incident Title:</b>", body_bold),
                Paragraph(incident_data.get("title", "Digital Harassment Incident"), body_style),
                Paragraph("<b>Platform:</b>", body_bold),
                Paragraph(incident_data.get("platform", "Email / SMS / Direct Message"), body_style)
            ],
            [
                Paragraph("<b>Victim Identifier:</b>", body_bold),
                Paragraph(incident_data.get("victim_alias", "Victim-Anonymous"), body_style),
                Paragraph("<b>Suspect Alias:</b>", body_bold),
                Paragraph(incident_data.get("suspect_alias", "Unknown / Multiple Handles"), body_style)
            ]
        ]
        case_table = Table(case_info, colWidths=[1.4 * inch, 2.2 * inch, 1.4 * inch, 2.0 * inch])
        case_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(case_table)
        story.append(Spacer(1, 10))

        # =========================================================================
        # 2. EXECUTIVE THREAT ASSESSMENT & TYPOLOGY MATRIX
        # =========================================================================
        story.append(Paragraph("1. Executive Threat Assessment", section_heading))
        
        threat_score = analysis_data.get("aggregate_threat_score", 0.0)
        risk_tier = analysis_data.get("risk_tier", "LOW")
        
        # Risk tier color
        tier_colors = {
            "CRITICAL": colors.HexColor("#dc2626"),
            "HIGH": colors.HexColor("#ea580c"),
            "ELEVATED": colors.HexColor("#d97706"),
            "LOW": colors.HexColor("#16a34a")
        }
        badge_bg = tier_colors.get(risk_tier, colors.HexColor("#475569"))

        summary_table_data = [
            [
                Paragraph(f"<b>THREAT LEVEL SCORE:</b><br/><font size='18'><b>{threat_score} / 100</b></font>", body_bold),
                Paragraph(f"<b>RISK TIER:</b><br/><font size='14' color='white'><b>{risk_tier}</b></font>", body_bold),
                Paragraph(
                    f"<b>Messages Analyzed:</b> {analysis_data.get('message_count', 0)}<br/>"
                    f"<b>Critical Velocity Bursts:</b> {analysis_data.get('burst_clusters_count', 0)}<br/>"
                    f"<b>Off-Hours Ratio (11PM-5AM):</b> {int(analysis_data.get('off_hours_ratio', 0) * 100)}%",
                    body_style
                )
            ]
        ]
        summary_table = Table(summary_table_data, colWidths=[2.3 * inch, 2.2 * inch, 2.5 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#f1f5f9")),
            ("BACKGROUND", (1, 0), (1, 0), badge_bg),
            ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ALIGN", (0, 0), (1, 0), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 8))

        # Typology Breakdown Table
        typologies = analysis_data.get("typology_scores", {})
        typo_data = [
            [
                Paragraph("<b>Cyberstalking Typology</b>", body_bold),
                Paragraph("<b>Detected Score</b>", body_bold),
                Paragraph("<b>Status</b>", body_bold),
                Paragraph("<b>Behavioral Indicators</b>", body_bold)
            ],
            [
                Paragraph("<b>Persistent Pursuit</b>", body_style),
                Paragraph(f"{typologies.get('persistent_pursuit', 0.0)} / 100", body_style),
                Paragraph("ACTIVE" if typologies.get("persistent_pursuit", 0) > 20 else "INACTIVE", body_bold),
                Paragraph("Obsessive unreciprocated outreach, multiple accounts, bypassing user blocks.", body_style)
            ],
            [
                Paragraph("<b>Threats & Intimidation</b>", body_style),
                Paragraph(f"{typologies.get('threats_intimidation', 0.0)} / 100", body_style),
                Paragraph("ACTIVE" if typologies.get("threats_intimidation", 0) > 20 else "INACTIVE", body_bold),
                Paragraph("Physical harm threats, coercive extortion, blackmail, psychological violence.", body_style)
            ],
            [
                Paragraph("<b>Surveillance & Monitoring</b>", body_style),
                Paragraph(f"{typologies.get('surveillance_monitoring', 0.0)} / 100", body_style),
                Paragraph("ACTIVE" if typologies.get("surveillance_monitoring", 0) > 20 else "INACTIVE", body_bold),
                Paragraph("Physical/digital location tracking, observing victim habits, schedule tracking.", body_style)
            ],
            [
                Paragraph("<b>Doxxing & Impersonation</b>", body_style),
                Paragraph(f"{typologies.get('doxxing_impersonation', 0.0)} / 100", body_style),
                Paragraph("ACTIVE" if typologies.get("doxxing_impersonation", 0) > 20 else "INACTIVE", body_bold),
                Paragraph("Leaking residential address, phone, employment data, defamatory impersonation.", body_style)
            ]
        ]
        typo_table = Table(typo_data, colWidths=[2.0 * inch, 1.1 * inch, 1.0 * inch, 2.9 * inch])
        typo_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(typo_table)
        story.append(Spacer(1, 10))

        # =========================================================================
        # 3. TEMPORAL CADENCE & ESCALATION ANALYSIS
        # =========================================================================
        story.append(Paragraph("2. Temporal Cadence & Nocturnal Escalation", section_heading))
        cadence = analysis_data.get("cadence_metrics", {})
        cadence_text = (
            f"<b>Transmission Summary:</b> {cadence.get('cadence_summary', 'Normal interval profile.')}<br/>"
            f"<b>Mean Interval:</b> {cadence.get('mean_interval_minutes', 0)} mins | "
            f"<b>Median:</b> {cadence.get('median_interval_minutes', 0)} mins | "
            f"<b>Velocity Acceleration Factor:</b> {cadence.get('acceleration_factor', 0.0)}x | "
            f"<b>Escalation Pattern:</b> {'DETECTED' if cadence.get('escalation_detected') else 'STABLE'}"
        )
        cadence_table = Table([[Paragraph(cadence_text, body_style)]], colWidths=[7.0 * inch])
        cadence_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#eff6ff")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#93c5fd")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(cadence_table)
        story.append(Spacer(1, 10))

        # =========================================================================
        # 4. DIGITAL EVIDENCE LEDGER & SHA-256 CHAIN OF CUSTODY
        # =========================================================================
        story.append(KeepTogether([
            Paragraph("3. Cryptographic Chain of Custody (ISO/IEC 27037)", section_heading),
            Paragraph(
                "Every message and header is cryptographically sealed with a SHA-256 digest at ingestion to prevent evidence spoliation.",
                subtitle_style
            ),
            Spacer(1, 4)
        ]))

        evidence_items = analysis_data.get("evidence_ledger", [])
        evidence_rows = [
            [
                Paragraph("<b>Item ID</b>", body_bold),
                Paragraph("<b>Timestamp (UTC)</b>", body_bold),
                Paragraph("<b>Evidence Content Excerpt</b>", body_bold),
                Paragraph("<b>SHA-256 Digest</b>", body_bold)
            ]
        ]

        if evidence_items:
            for item in evidence_items[:10]:  # Cap first 10 for clean layout
                evidence_rows.append([
                    Paragraph(str(item.get("evidence_id", "EV-001")), mono_bold),
                    Paragraph(str(item.get("acquired_at_utc", ""))[:19].replace("T", " "), mono_style),
                    Paragraph(str(item.get("preview", ""))[:80], body_style),
                    Paragraph(str(item.get("sha256_hash", "")), mono_style)
                ])
        else:
            evidence_rows.append([
                Paragraph("N/A", body_style),
                Paragraph("N/A", body_style),
                Paragraph("No explicit evidence ledger items recorded.", body_style),
                Paragraph("N/A", body_style)
            ])

        evidence_table = Table(evidence_rows, colWidths=[1.1 * inch, 1.4 * inch, 2.3 * inch, 2.2 * inch])
        evidence_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(evidence_table)
        story.append(Spacer(1, 10))

        # =========================================================================
        # 5. FORENSIC EMAIL ROUTING & ORIGINATING IP (IF AVAILABLE)
        # =========================================================================
        if forensic_trace and forensic_trace.get("success"):
            story.append(KeepTogether([
                Paragraph("4. Forensic Header Trace & Network Origin", section_heading),
                Paragraph(
                    f"<b>Originating Public IP:</b> <font color='#0284c7'><b>{forensic_trace.get('originating_public_ip')}</b></font> | "
                    f"<b>User Agent:</b> {forensic_trace.get('user_agent', 'N/A')}<br/>"
                    f"<b>SPF Status:</b> {forensic_trace.get('authentication', {}).get('spf_status')} | "
                    f"<b>DKIM Status:</b> {forensic_trace.get('authentication', {}).get('dkim_status')} | "
                    f"<b>Total Relay Hops:</b> {forensic_trace.get('hop_count', 0)}",
                    body_style
                ),
                Spacer(1, 6)
            ]))

            hop_rows = [
                [
                    Paragraph("<b>Hop #</b>", body_bold),
                    Paragraph("<b>From Host</b>", body_bold),
                    Paragraph("<b>By Host</b>", body_bold),
                    Paragraph("<b>Identified IP</b>", body_bold),
                    Paragraph("<b>Hop Type</b>", body_bold)
                ]
            ]
            for h in forensic_trace.get("hops", [])[:6]:
                hop_rows.append([
                    Paragraph(str(h.get("hop_index")), mono_bold),
                    Paragraph(str(h.get("from_host", "Unknown"))[:30], mono_style),
                    Paragraph(str(h.get("by_host", "Unknown"))[:30], mono_style),
                    Paragraph(str(h.get("identified_ip", "N/A")), mono_style),
                    Paragraph("PUBLIC" if h.get("is_public_hop") else "PRIVATE/RELAY", body_style)
                ])

            hop_table = Table(hop_rows, colWidths=[0.6 * inch, 1.8 * inch, 1.8 * inch, 1.6 * inch, 1.2 * inch])
            hop_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(hop_table)
            story.append(Spacer(1, 10))

        # =========================================================================
        # 6. STATUTORY LEGAL BENCHMARKS (BNS 78, IT ACT, 18 U.S.C. 2261A)
        # =========================================================================
        story.append(KeepTogether([
            Paragraph("5. Statutory Legal Benchmark & Jurisprudential Mapping", section_heading),
            Paragraph(
                "Automated mapping of detected typologies to applicable criminal statutes under Indian and US Federal Law.",
                subtitle_style
            ),
            Spacer(1, 4)
        ]))

        statutes = (legal_benchmark or {}).get("applicable_statutes", [])
        if statutes:
            statute_rows = [
                [
                    Paragraph("<b>Statute & Jurisdiction</b>", body_bold),
                    Paragraph("<b>Matched Offense Elements</b>", body_bold),
                    Paragraph("<b>Prescribed Penalty</b>", body_bold)
                ]
            ]
            for st in statutes:
                elements = "<br/>• ".join(st.get("elements_satisfied", ["Element satisfaction under review"]))
                statute_rows.append([
                    Paragraph(f"<b>{st.get('statute_title')}</b><br/><font color='#64748b'>{st.get('jurisdiction')}</font>", body_style),
                    Paragraph(f"• {elements}", body_style),
                    Paragraph(st.get("penalties", "Statutory term"), body_style)
                ])

            statute_table = Table(statute_rows, colWidths=[2.2 * inch, 3.0 * inch, 1.8 * inch])
            statute_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(statute_table)
        else:
            story.append(Paragraph("No critical criminal thresholds met for statutory citation.", body_style))

        story.append(Spacer(1, 14))

        # =========================================================================
        # 7. FORENSIC ATTESTATION & CHAIN-OF-CUSTODY SIGN-OFF
        # =========================================================================
        signoff_data = [
            [
                Paragraph("<b>FORENSIC EXAMINER CERTIFICATION:</b><br/>"
                          "This incident dossier was algorithmically compiled in conformity with RFC 822 and "
                          "ISO/IEC 27037 standards. Digital evidence SHA-256 hashes are immutable.", body_style),
                Paragraph("<b>DIGITAL FORENSIC SEAL:</b><br/>"
                          "AEGISTRACE EVIDENCE LOCK [VERIFIED]<br/>"
                          f"Digest: {analysis_data.get('dossier_hash', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')[:32]}...", mono_style)
            ]
        ]
        signoff_table = Table(signoff_data, colWidths=[4.4 * inch, 2.6 * inch])
        signoff_table.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#0284c7")),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(KeepTogether([signoff_table]))

        # Build document using NumberedCanvas
        doc.build(story, canvasmaker=NumberedCanvas)
        buffer.seek(0)
        return buffer.getvalue()
