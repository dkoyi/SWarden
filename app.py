"""
SWarden: Zero-Trust Threat & Exfiltration Auditor
==================================================
Powered by Snowflake Cortex AI (Llama 3.1), Snowflake CoCo, and IPinfo Marketplace Data.

Architecture:
  - Snowflake connection via snowflake-connector-python + python-dotenv (.env)
  - CoCo-generated SQL joins SESSION_ACTIVITY with IPinfo LITE dataset
  - Risk scoring via inline IFF expressions (geo-anomaly, cloud ASN, mass row scan)
  - Cortex AI (Llama 3.1 inside warehouse) generates incident response + DDL

Launch:
  streamlit run app.py
"""

import os
import json
import datetime

import streamlit as st
import snowflake.connector
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# ── Load environment variables from .env ──────────────────────────────────────
load_dotenv()

SNOWFLAKE_ACCOUNT    = os.getenv("SNOWFLAKE_ACCOUNT", "")
SNOWFLAKE_USER       = os.getenv("SNOWFLAKE_USER", "")
SNOWFLAKE_WAREHOUSE  = os.getenv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH")
SNOWFLAKE_ROLE       = os.getenv("SNOWFLAKE_ROLE", "ACCOUNTADMIN")
RSA_KEY_PATH         = os.getenv("RSA_KEY_PATH", "rsa_key.p8")

# ── Page config (must be FIRST Streamlit call) ────────────────────────────────
st.set_page_config(
    page_title="SWarden – Zero-Trust Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Inline dark-mode CSS (premium overhaul) ──────────────────────────────
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
    html,body,[data-testid="stAppViewContainer"]{background:#060d18!important;color:#c9d1d9!important;font-family:'Inter','Segoe UI',system-ui,sans-serif;}
    [data-testid="stHeader"]{background:transparent!important;}
    .metric-row{display:flex;gap:.85rem;margin-top:1.1rem;}
    .metric-card{flex:1;background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:.9rem 1rem;text-align:center;transition:border-color .2s,box-shadow .2s;}
    .metric-card:hover{border-color:#388bfd;box-shadow:0 0 14px rgba(56,139,253,.18);}
    .metric-card .val{font-size:1.9rem;font-weight:800;color:#58a6ff;line-height:1.1;}
    .metric-card .lbl{font-size:.68rem;color:#6e7681;margin-top:.3rem;text-transform:uppercase;letter-spacing:.07em;font-weight:600;}
    .metric-card.danger .val{color:#f85149;}.metric-card.danger:hover{border-color:#f85149;box-shadow:0 0 14px rgba(248,81,73,.18);}
    .metric-card.warn .val{color:#e3b341;}.metric-card.warn:hover{border-color:#e3b341;box-shadow:0 0 14px rgba(227,179,65,.18);}
    .alert-critical{background:linear-gradient(90deg,rgba(61,0,20,.95),rgba(28,0,16,.95));border:1px solid #f85149;border-radius:10px;padding:1rem 1.4rem;color:#f85149;font-weight:800;font-size:1.05rem;margin-bottom:1rem;animation:pulse-border 2s ease-in-out infinite;}
    @keyframes pulse-border{0%,100%{box-shadow:0 0 24px rgba(248,81,73,.25);}50%{box-shadow:0 0 40px rgba(248,81,73,.5);}}
    .section-title{font-size:.78rem;font-weight:700;color:#79c0ff;border-bottom:1px solid #21262d;padding-bottom:.4rem;margin-bottom:1rem;text-transform:uppercase;letter-spacing:.1em;}
    .dossier{background:linear-gradient(145deg,#0f1923,#0d1117);border:1px solid #30363d;border-top:2px solid #f0883e;border-radius:10px;padding:1.1rem 1.3rem;margin:.8rem 0;box-shadow:0 4px 24px rgba(0,0,0,.5);}
    .dossier-label{font-size:.65rem;font-weight:700;color:#6e7681;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.15rem;}
    .dossier-value{font-size:.95rem;font-weight:600;color:#e6edf3;word-break:break-all;}
    .dossier-value.highlight{color:#f0883e;}.dossier-value.ip{color:#79c0ff;font-family:monospace;}.dossier-value.role{color:#d2a8ff;}
    .dossier-row{display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin-bottom:.75rem;}
    .dossier-row.full{grid-template-columns:1fr;}
    .dossier-divider{border:none;border-top:1px solid #21262d;margin:.75rem 0;}
    [data-testid="stMetric"]{background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:.75rem 1rem;transition:border-color .2s,box-shadow .2s;}
    [data-testid="stMetric"]:hover{border-color:#388bfd;box-shadow:0 0 12px rgba(56,139,253,.15);}
    [data-testid="stMetricLabel"]>div{font-size:.68rem!important;font-weight:700!important;text-transform:uppercase;letter-spacing:.07em;color:#6e7681!important;}
    [data-testid="stMetricValue"]>div{font-size:1.6rem!important;font-weight:800!important;color:#58a6ff!important;}
    button[data-testid="baseButton-primary"]{background:linear-gradient(135deg,#b91c1c,#7f1d1d)!important;color:#fff!important;border:1px solid #ef4444!important;border-radius:8px!important;font-weight:700!important;animation:lockdown-pulse 2.5s ease-in-out infinite;}
    @keyframes lockdown-pulse{0%,100%{box-shadow:0 0 18px rgba(239,68,68,.3);}50%{box-shadow:0 0 36px rgba(239,68,68,.6);}}
    button[data-testid="baseButton-primary"]:hover{opacity:.88!important;transform:translateY(-1px);}
    button[data-testid="baseButton-secondary"]{background:linear-gradient(135deg,#238636,#196127)!important;color:#fff!important;border:1px solid #2ea043!important;border-radius:8px!important;font-weight:600!important;transition:opacity .15s!important;}
    button[data-testid="baseButton-secondary"]:hover{opacity:.85!important;}
    [data-testid="stDataFrame"]{border-radius:10px;overflow:hidden;border:1px solid #21262d;box-shadow:0 2px 12px rgba(0,0,0,.4);}
    .ai-response{background:#0d1117;border:1px solid #30363d;border-left:3px solid #58a6ff;border-radius:8px;padding:1rem 1.2rem;font-size:.9rem;line-height:1.7;margin-top:.6rem;}
    .pill{display:inline-block;padding:.2rem .65rem;border-radius:20px;font-size:.7rem;font-weight:700;letter-spacing:.04em;}
    .pill-green{background:#1f4a26;color:#56d364;border:1px solid #2ea043;}
    .pill-red{background:#3d0014;color:#f85149;border:1px solid #f85149;}
    .stButton>button {
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        border-color: #29B5E8 !important;
        color: #29B5E8 !important;
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(41, 181, 232, 0.25);
    }
    [data-testid="stDataFrame"] {
        transition: transform 0.2s ease;
    }
    [data-testid="stDataFrame"]:hover {
        transform: translateY(-1px);
        box-shadow: 0 6px 14px rgba(0, 0, 0, 0.15);
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── CoCo-generated SQL (verbatim from specification) ─────────────────────────
COCO_THREAT_QUERY = """
SELECT
    s.event_time,
    s.username,
    s.role_used,
    s.client_ip,
    s.query_text,
    s.rows_scanned,
    COALESCE(i.country, 'Unknown') AS country,
    COALESCE(i.as_name, 'Unknown') AS asn_name,
    (
        IFF(i.country_code IS DISTINCT FROM 'US', 30, 0)
        + IFF(i.as_name ILIKE '%DigitalOcean%' OR i.as_name ILIKE '%Amazon%', 30, 0)
        + IFF(s.rows_scanned > 100000, 40, 0)
    ) AS risk_score
FROM SWARDEN_DB.PUBLIC.SESSION_ACTIVITY s
LEFT JOIN IPINFO_LITE.PUBLIC.LITE i
ON PARSE_IP(s.client_ip, 'inet'):ipv4::INT
    BETWEEN TRY_CAST(i.start_ip_int::VARCHAR AS BIGINT)
        AND TRY_CAST(i.end_ip_int::VARCHAR AS BIGINT)
ORDER BY risk_score DESC NULLS LAST, s.event_time DESC
"""


# ── Helper: load RSA private key → DER bytes ─────────────────────────────────
def _load_private_key_bytes(key_path: str) -> bytes:
    """
    Reads rsa_key.p8 (PKCS8 PEM, unencrypted), converts to DER bytes
    suitable for snowflake.connector.connect(private_key=...).
    Raises FileNotFoundError or ValueError with a user-friendly message.
    """
    if not os.path.exists(key_path):
        raise FileNotFoundError(
            f"RSA private key not found at `{key_path}`.\n"
            "Run `python genkeys.py` to generate a new key pair."
        )

    with open(key_path, "rb") as key_file:
        p_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    return p_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


# ── Helper: Snowflake connection (RSA Key-Pair Auth) ──────────────────────────
def get_db_connection():
    """
    Returns a cached snowflake-connector-python connection stored in
    st.session_state, authenticated via RSA key-pair (no password).
    Validates required env-vars and the presence of rsa_key.p8 before connecting.
    """
    if "sf_conn" in st.session_state and st.session_state["sf_conn"] is not None:
        return st.session_state["sf_conn"]

    # ── Env-var validation ───────────────────────────────────────────────────
    missing = [
        v for v in ("SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER")
        if not os.getenv(v)
    ]
    if missing:
        st.error(
            f"❌ Missing required environment variables: `{', '.join(missing)}`.\n\n"
            "Ensure `SNOWFLAKE_ACCOUNT` and `SNOWFLAKE_USER` are set in your `.env` file.",
            icon="🔐",
        )
        return None

    # ── RSA key load ─────────────────────────────────────────────────────────
    try:
        pkb = _load_private_key_bytes(RSA_KEY_PATH)
    except FileNotFoundError as exc:
        st.error(f"❌ {exc}", icon="🗝️")
        return None
    except Exception as exc:
        st.error(
            f"❌ Failed to load RSA private key: `{exc}`\n\n"
            "Ensure `rsa_key.p8` is a valid unencrypted PKCS8 PEM file.",
            icon="🗝️",
        )
        return None

    # ── Connect ──────────────────────────────────────────────────────────────
    try:
        conn = snowflake.connector.connect(
            account=os.getenv("SNOWFLAKE_ACCOUNT"),
            user=os.getenv("SNOWFLAKE_USER"),
            private_key=pkb,
            warehouse=os.getenv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH"),
            role=os.getenv("SNOWFLAKE_ROLE", "ACCOUNTADMIN"),
        )
        st.session_state["sf_conn"] = conn
        return conn
    except Exception as exc:
        st.error(
            f"❌ Snowflake connection failed: `{exc}`\n\n"
            "Verify your account identifier, username, and that the public key is registered "
            "in Snowflake (`ALTER USER <user> SET RSA_PUBLIC_KEY='...'`).",
            icon="🚨",
        )
        return None


# ── Helper: serialise rows (datetime / Decimal → str) ────────────────────────
def _serialize_row(row: dict) -> dict:
    """
    Convert all non-JSON-serialisable types (datetime, Decimal, etc.)
    to plain strings so they can be safely embedded in prompt f-strings
    or passed to json.dumps without raising TypeError.
    """
    safe = {}
    for k, v in row.items():
        if isinstance(v, (datetime.datetime, datetime.date, datetime.time)):
            safe[k] = v.isoformat()
        else:
            try:
                json.dumps(v)      # test serializability
                safe[k] = v
            except (TypeError, ValueError):
                safe[k] = str(v)
    return safe


# ── Data engine: CoCo query ───────────────────────────────────────────────────
def fetch_threat_intel(conn) -> list:
    """
    Execute the Snowflake Cortex Code (CoCo) generated SQL and return
    a list of row dicts.  Results are cached in st.session_state["records"].
    """
    try:
        cursor = conn.cursor()
        cursor.execute(COCO_THREAT_QUERY)
        columns = [col[0].lower() for col in cursor.description]
        rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
        cursor.close()
        return rows
    except Exception as exc:
        st.error(
            f"❌ Threat Intel query failed: `{exc}`\n\n"
            "Ensure `SWARDEN_DB.PUBLIC.SESSION_ACTIVITY` and "
            "`IPINFO_LITE.PUBLIC.LITE` are accessible in your account.",
            icon="⚠️",
        )
        return []


# ── Cortex AI: Llama 3.1 incident response ───────────────────────────────────
def run_cortex_ai(conn, event: dict) -> str:
    """
    Calls SNOWFLAKE.CORTEX.COMPLETE('llama3.1-8b', <prompt>) inside the
    warehouse and returns the model's text response.

    The event dict is guaranteed to be fully JSON-safe before this call
    (all datetime/Decimal values already serialised to strings by _serialize_row).
    """
    username  = event.get("username",  "<unknown>")
    role_used = event.get("role_used", "<unknown>")
    client_ip = event.get("client_ip", "<unknown>")
    country   = event.get("country",   "<unknown>")
    asn_name  = event.get("asn_name",  "<unknown>")
    rows_scan = event.get("rows_scanned", 0)
    risk      = event.get("risk_score", 0)
    event_ts  = event.get("event_time", "<unknown>")
    query_txt = str(event.get("query_text", "")).replace("'", "''")[:300]

    system_prompt = (
        f"You are SWarden, an elite Zero-Trust Security Operations AI. "
        f"A CRITICAL threat event has been detected in the Snowflake data platform. "
        f"Analyse the following telemetry and produce a concise incident report.\n\n"
        f"=== THREAT TELEMETRY ===\n"
        f"Timestamp   : {event_ts}\n"
        f"Username    : {username}\n"
        f"Role Used   : {role_used}\n"
        f"Client IP   : {client_ip}\n"
        f"Country     : {country}\n"
        f"ASN         : {asn_name}\n"
        f"Rows Scanned: {rows_scan}\n"
        f"Risk Score  : {risk}/100\n"
        f"Query Text  : {query_txt}\n\n"
        f"=== INSTRUCTIONS ===\n"
        f"1. Briefly summarise the THREE active threat vectors detected:\n"
        f"   a) Geo-anomaly  - login from non-US country ({country})\n"
        f"   b) Cloud ASN Hosting - traffic from cloud provider ASN ({asn_name})\n"
        f"   c) Mass Data Exfiltration - {rows_scan} rows scanned in a single session\n\n"
        f"2. Provide an IMMEDIATE Threat Containment section with EXACTLY this DDL:\n\n"
        f"ALTER USER {username} ABORT ALL SESSIONS;\n"
        f"ALTER USER {username} SET DISABLED = TRUE;\n"
        f"REVOKE ROLE {role_used} FROM USER {username};\n\n"
        f"3. Suggest 2-3 forensic next steps a SOC analyst should take.\n"
        f"Be concise, professional, and use markdown formatting."
    )

    # Escape single quotes for embedding in SQL string literal
    escaped_prompt = system_prompt.replace("'", "''")

    cortex_sql = f"SELECT SNOWFLAKE.CORTEX.COMPLETE('llama3.1-8b', '{escaped_prompt}') AS response"

    try:
        cursor = conn.cursor()
        cursor.execute(cortex_sql)
        result = cursor.fetchone()
        cursor.close()
        if result:
            return result[0]
        return "⚠️ Cortex AI returned an empty response."
    except Exception as exc:
        return (
            f"❌ Cortex AI call failed: {exc}\n\n"
            "Ensure SNOWFLAKE.CORTEX.COMPLETE is available in your account region "
            "and that llama3.1-8b is an enabled model."
        )

# ── Main UI ───────────────────────────────────────────────────────────────────────────────────
def main():
    import pandas as pd
    import os

    # ── Sidebar ────────────────────────────────────────────
    with st.sidebar:
        st.markdown("### 🛡️ SWarden Control Center")
        st.success("Database: Connected (RSA Secure)")
        st.info("Cortex AI: Online (Llama 3.1 8B)")
        st.caption("Telemetry: IPinfo Marketplace Active")

    # ── Page Header ────────────────────────────────────────────────────────────────────────────────────
    st.markdown(
        """
        <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; padding-bottom: 2rem;">
            <div style="display: flex; align-items: center; justify-content: center; gap: 15px;">
                <div style="display: flex; flex-direction: column; align-items: center; justify-content: center;">
                    <h1 style="font-size: 6rem; margin: 0; color: #FFFFFF; line-height: 1;">SWarden</h1>
                    <h2 style="font-size: 1.6rem; color: #A3B8CC; font-weight: 400; margin-top: 2px; margin-bottom: 0;">Zero-Trust Threat & Exfiltration Auditor</h2>
                </div>
                <span style="font-size: 8rem; line-height: 1;">🛡️</span>
            </div>
            <div style="margin-top: 30px; background: rgba(41, 181, 232, 0.1); border: 1px solid #29B5E8; color: #29B5E8; padding: 6px 16px; border-radius: 20px; font-size: 0.85rem; font-weight: 600; letter-spacing: 1.5px; box-shadow: 0 0 10px rgba(41, 181, 232, 0.2);">
                SYSTEM ONLINE • RSA SECURE CONNECTION
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ════════════════════════════════════════════════════════════════════════════
    # Active Threat Monitor
    # ════════════════════════════════════════════════════════════════════════════
    st.markdown("<div style='margin-top: 1rem;'></div>", unsafe_allow_html=True)
    run_scan = st.button("🔍 Run Threat Scan", key="btn_scan")

    if run_scan:
        conn = get_db_connection()
        if conn:
            with st.spinner("Executing CoCo threat-intel query…"):
                records = fetch_threat_intel(conn)
            if records:
                st.session_state["records"] = records
                st.session_state.pop("ai_response", None)
            else:
                st.warning("0 rows returned. Check table population.", icon="📭")

    records = st.session_state.get("records", [])

    if not records:
        st.markdown(
            """
            <div style="text-align:center;padding:4rem 2rem;color:#6e7681;">
                <div style="font-size:3rem;margin-bottom:.75rem;">🛡️</div>
                <div style="font-size:1.1rem;font-weight:600;color:#8b949e;">No scan data yet</div>
                <div style="font-size:.88rem;margin-top:.4rem;">
                    Click <strong style="color:#58a6ff;">Run Threat Scan</strong> above to pull live telemetry.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        col1, col2 = st.columns([6, 4], gap="large")

        with col1:
            st.markdown('<div class="section-title">📡 Live Network Intent Monitor</div>', unsafe_allow_html=True)
            df = pd.DataFrame(records)
            st.dataframe(
                df,
                width="stretch",
                hide_index=True,
                column_config={
                    "event_time":   st.column_config.DatetimeColumn("Event Time", format="YYYY-MM-DD HH:mm:ss"),
                    "username":     st.column_config.TextColumn("User"),
                    "role_used":    st.column_config.TextColumn("Target Role"),
                    "client_ip":    st.column_config.TextColumn("Client IP"),
                    "query_text":   st.column_config.TextColumn("Query Preview", max_chars=60),
                    "rows_scanned": st.column_config.NumberColumn("Rows Scanned", format="%d"),
                    "country":      st.column_config.TextColumn("Country"),
                    "asn_name":     st.column_config.TextColumn("ASN / Carrier"),
                    "risk_score":   st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%f"),
                },
            )

            total  = len(records)
            crits  = sum(1 for r in records if (r.get("risk_score") or 0) >= 65)
            scores = [r.get("risk_score") or 0 for r in records]
            avg    = round(sum(scores) / len(scores), 1) if scores else 0

            st.markdown(
                f"""
                <div class="metric-row">
                    <div class="metric-card">
                        <div class="val">{total}</div>
                        <div class="lbl">Sessions Scanned</div>
                    </div>
                    <div class="metric-card danger">
                        <div class="val">{crits}</div>
                        <div class="lbl">Critical Alerts (&ge;65)</div>
                    </div>
                    <div class="metric-card warn">
                        <div class="val">{avg}</div>
                        <div class="lbl">Avg Risk Score</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with col2:
            st.markdown('<div class="section-title">🤖 Cortex AI SecOps Engine</div>', unsafe_allow_html=True)
            top_event_raw = max(records, key=lambda r: r.get("risk_score") or 0)
            top_event     = _serialize_row(top_event_raw)
            top_score     = top_event.get("risk_score") or 0

            if top_score >= 65:
                st.markdown(
                    f'<div class="alert-critical">🚨 CRITICAL THREAT DETECTED: Risk Score {top_score}/100</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.info(f"ℹ️ Highest risk score: **{top_score}/100** — below threshold (65).", icon="🔵")

            st.markdown(
                '<div class="section-title" style="margin-top:.5rem;">📋 Threat Dossier — Highest-Risk Actor</div>',
                unsafe_allow_html=True,
            )
            m1, m2 = st.columns(2)
            m1.metric(label="☠️ Compromised User", value=top_event.get("username") or "—")
            m2.metric(
                label="🎯 Risk Score",
                value=f"{top_score} / 100",
                delta="CRITICAL" if top_score >= 65 else "ELEVATED",
                delta_color="inverse" if top_score >= 65 else "off",
            )

            rows_val = top_event.get("rows_scanned", 0)
            rows_fmt = f"{int(rows_val):,}" if isinstance(rows_val, (int, float)) else str(rows_val)

            st.markdown(
                f"""
                <div class="dossier">
                    <div class="dossier-row">
                        <div><div class="dossier-label">Origin Country</div>
                             <div class="dossier-value highlight">{top_event.get('country', 'Unknown')}</div></div>
                        <div><div class="dossier-label">Rogue IP Address</div>
                             <div class="dossier-value ip">{top_event.get('client_ip', '—')}</div></div>
                    </div>
                    <div class="dossier-row">
                        <div><div class="dossier-label">ASN Infrastructure</div>
                             <div class="dossier-value">{top_event.get('asn_name', 'Unknown')}</div></div>
                        <div><div class="dossier-label">Rows Exfiltrated</div>
                             <div class="dossier-value" style="color:#f85149;font-weight:800;">{rows_fmt}</div></div>
                    </div>
                    <hr class="dossier-divider">
                    <div class="dossier-row full">
                        <div><div class="dossier-label">Abused Role</div>
                             <div class="dossier-value role">{top_event.get('role_used', '—')}</div></div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            query_preview = str(top_event.get("query_text") or "— no query captured —")
            st.markdown('<div class="dossier-label" style="margin-bottom:.35rem;">🔎 Captured Query</div>', unsafe_allow_html=True)
            st.code(query_preview, language="sql")

            st.markdown("<div style='margin-top:.5rem;'></div>", unsafe_allow_html=True)
            gen_response = st.button(
                "⚡ INITIATE CORTEX AI LOCKDOWN",
                key="btn_cortex",
                type="primary",
                use_container_width=True,
            )
            if gen_response:
                conn = get_db_connection()
                if conn:
                    with st.spinner("Calling SNOWFLAKE.CORTEX.COMPLETE('llama3.1-8b', …) inside warehouse…"):
                        ai_text = run_cortex_ai(conn, top_event)
                    st.session_state["ai_response"] = ai_text

            if "ai_response" in st.session_state:
                st.markdown("---")
                st.markdown('<div class="section-title">🧠 Llama 3.1 Incident Report</div>', unsafe_allow_html=True)
                st.markdown(st.session_state["ai_response"])

    # ════════════════════════════════════════════════════════════════════════════
    # Cortex SecOps Copilot (Text-to-SQL chat interface)
    # ════════════════════════════════════════════════════════════════════════════
    st.divider()

    if "records" not in st.session_state or not st.session_state["records"]:
        st.info("ℹ️ Run a Threat Scan above to initialize the Cortex AI Copilot.")
    else:
        with st.expander("🤖 Chat with Cortex SecOps Copilot", expanded=True):
            st.markdown(
                """
                <div style="padding:0 0 1rem;">
                    <p style="color:#8b949e;font-size:.88rem;margin:0;">
                        Ask Cortex AI to query your security logs in plain English.
                        The Copilot translates your question into Snowflake SQL and executes it live.
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if "copilot_messages" not in st.session_state:
                st.session_state["copilot_messages"] = []

            for msg in st.session_state["copilot_messages"]:
                with st.chat_message(msg["role"], avatar="🛡️" if msg["role"] == "assistant" else "👤"):
                    st.markdown(msg["content"])
                    if "dataframe" in msg:
                        st.dataframe(
                            msg["dataframe"],
                            width="stretch",
                            hide_index=True,
                            column_config={
                                "risk_score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%f"),
                                "rows_scanned": st.column_config.NumberColumn("Rows Scanned", format="%d"),
                                "event_time": st.column_config.DatetimeColumn("Event Time", format="YYYY-MM-DD HH:mm:ss"),
                            },
                        )
                    if "sql" in msg:
                        with st.expander("📄 Generated SQL", expanded=False):
                            st.code(msg["sql"], language="sql")

            user_q = st.chat_input("Ask Cortex to query your security logs (e.g. 'Show me admin logins from non-US IPs')…")

            if user_q:
                st.session_state["copilot_messages"].append({"role": "user", "content": user_q})
                with st.chat_message("user", avatar="👤"):
                    st.write(user_q)

                conn = get_db_connection()
                if not conn:
                    with st.chat_message("assistant", avatar="🛡️"):
                        st.error("No Snowflake connection. Run the Threat Scan first to establish a connection.", icon="🔌")
                else:
                    escaped_q = user_q.replace("'", "''")
                    prompt = f"""
You are a Snowflake SQL expert. Generate ONLY a valid Snowflake SQL query based on the user's request. Do not include markdown formatting, backticks, or explanations.
Always use the fully qualified table names SWARDEN_DB.PUBLIC.SESSION_ACTIVITY and IPINFO_LITE.PUBLIC.LITE. Never use unqualified table names.

Schema:
Table: SWARDEN_DB.PUBLIC.SESSION_ACTIVITY
Columns: event_time (TIMESTAMP), username (VARCHAR), role_used (VARCHAR), client_ip (VARCHAR), query_text (VARCHAR), rows_scanned (NUMBER)

User Request: {escaped_q}

SQL Query:
"""
                    cortex_prompt = prompt.replace("'", "''")
                    cortex_sql_req = f"SELECT SNOWFLAKE.CORTEX.COMPLETE('llama3.1-8b', '{cortex_prompt}') AS sql_output"

                    with st.spinner("🧠 Cortex is translating your question into SQL…"):
                        try:
                            cur = conn.cursor()
                            cur.execute(cortex_sql_req)
                            row = cur.fetchone()
                            cur.close()
                            ai_sql = (row[0] or "").strip() if row else ""

                            ai_sql = ai_sql.replace("```sql", "").replace("```", "").strip()

                        except Exception as exc:
                            ai_sql = ""
                            with st.chat_message("assistant", avatar="🛡️"):
                                st.error(f"Cortex AI call failed: {exc}", icon="🧠")
                            st.session_state["copilot_messages"].append({
                                "role": "assistant",
                                "content": f"❌ Cortex AI call failed: {exc}",
                            })
                            st.stop()

                    result_df = None
                    exec_error = None
                    if ai_sql:
                        try:
                            cur2 = conn.cursor()
                            cur2.execute(ai_sql)
                            cols = [d[0].lower() for d in cur2.description]
                            rows = cur2.fetchall()
                            cur2.close()
                            import pandas as pd
                            result_df = pd.DataFrame(rows, columns=cols)
                        except Exception as exc:
                            exec_error = str(exc)

                    with st.chat_message("assistant", avatar="🛡️"):
                        if exec_error:
                            reply = (
                                f"⚠️ The generated SQL could not be executed:\n\n"
                                f"**Error:** `{exec_error}`\n\n"
                                f"Try rephrasing your question or be more specific about the columns you need."
                            )
                            st.markdown(reply)
                            with st.expander("📄 Attempted SQL", expanded=True):
                                st.code(ai_sql, language="sql")
                            st.session_state["copilot_messages"].append({
                                "role": "assistant",
                                "content": reply,
                                "sql": ai_sql,
                            })
                        elif result_df is not None and not result_df.empty:
                            reply = f"✅ Query returned **{len(result_df)} row(s)**."
                            st.markdown(reply)
                            st.dataframe(
                                result_df,
                                width="stretch",
                                hide_index=True,
                                column_config={
                                    "risk_score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%f"),
                                    "rows_scanned": st.column_config.NumberColumn("Rows Scanned", format="%d"),
                                    "event_time": st.column_config.DatetimeColumn("Event Time", format="YYYY-MM-DD HH:mm:ss"),
                                },
                            )
                            with st.expander("📄 Generated SQL", expanded=False):
                                st.code(ai_sql, language="sql")
                            st.session_state["copilot_messages"].append({
                                "role": "assistant",
                                "content": reply,
                                "sql": ai_sql,
                                "dataframe": result_df,
                            })
                        elif result_df is not None and result_df.empty:
                            reply = "📭 The query executed successfully but returned 0 rows."
                            st.markdown(reply)
                            with st.expander("📄 Generated SQL", expanded=False):
                                st.code(ai_sql, language="sql")
                            st.session_state["copilot_messages"].append({
                                "role": "assistant",
                                "content": reply,
                                "sql": ai_sql,
                            })
                        else:
                            reply = "⚠️ Cortex returned an empty response. Please try again."
                            st.markdown(reply)
                            st.session_state["copilot_messages"].append({
                                "role": "assistant",
                                "content": reply,
                            })

if __name__ == "__main__":
    main()
