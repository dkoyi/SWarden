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
    initial_sidebar_state="collapsed",
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


# ── Main UI ───────────────────────────────────────────────────────────────────
def main():
    # ── App header ──────────────────────────────────────────────────────────
    st.markdown(
        """
        <div style="text-align:center; padding: 1.2rem 0 .6rem;">
            <h1 style="font-size:2rem; font-weight:800; color:#f0f6fc; margin:0;">
                🛡️ SWarden: Zero-Trust Threat &amp; Exfiltration Auditor
            </h1>
            <p style="color:#8b949e; margin:.4rem 0 0; font-size:.95rem;">
                Powered by Snowflake Cortex AI (Llama 3.1), Snowflake CoCo, and IPinfo Marketplace Data
            </p>
        </div>
        <hr style="border:none; border-top:1px solid #21262d; margin:.8rem 0 1.4rem;">
        """,
        unsafe_allow_html=True,
    )

    # ── Connection status badge ──────────────────────────────────────────────
    env_ok = all([SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER]) and os.path.exists(RSA_KEY_PATH)
    badge = (
        '<span class="pill pill-green">&#9679; ENV LOADED</span>'
        if env_ok
        else '<span class="pill pill-red">&#9679; ENV MISSING</span>'
    )
    st.markdown(
        f"<div style='margin-bottom:.8rem;'>{badge} &nbsp;"
        f"Account: <code style='color:#79c0ff;'>{SNOWFLAKE_ACCOUNT or '—'}</code> &nbsp;|&nbsp; "
        f"Warehouse: <code style='color:#79c0ff;'>{SNOWFLAKE_WAREHOUSE}</code> &nbsp;|&nbsp; "
        f"Role: <code style='color:#79c0ff;'>{SNOWFLAKE_ROLE}</code></div>",
        unsafe_allow_html=True,
    )

    # ── 2-column layout (60 / 40) ────────────────────────────────────────────
    col_left, col_right = st.columns([3, 2], gap="large")

    # ════════════════════════════════════════════════════════════════════════
    # LEFT COLUMN — 📡 Live Network Intent Monitor
    # ════════════════════════════════════════════════════════════════════════
    with col_left:
        st.markdown(
            '<div class="section-title">📡 Live Network Intent Monitor</div>',
            unsafe_allow_html=True,
        )

        run_scan = st.button("🔍 Run Threat Scan", key="btn_scan")

        if run_scan:
            conn = get_db_connection()
            if conn:
                with st.spinner("Executing CoCo threat-intel query against Snowflake…"):
                    records = fetch_threat_intel(conn)
                if records:
                    st.session_state["records"] = records
                    st.success(f"✅ Scan complete — {len(records)} sessions retrieved.", icon="🛰️")
                else:
                    st.warning("Query returned 0 rows. Check table population.", icon="📭")

        records = st.session_state.get("records", [])

        if records:
            import pandas as pd

            df = pd.DataFrame(records)

            # Display interactive dataframe with human-readable column config
            st.dataframe(
                df,
                width="stretch",
                hide_index=True,
                column_config={
                    "event_time": st.column_config.DatetimeColumn(
                        "Event Time",
                        format="YYYY-MM-DD HH:mm:ss",
                    ),
                    "username": st.column_config.TextColumn("User"),
                    "role_used": st.column_config.TextColumn("Target Role"),
                    "client_ip": st.column_config.TextColumn("Client IP"),
                    "query_text": st.column_config.TextColumn(
                        "Query Preview",
                        max_chars=60,
                    ),
                    "rows_scanned": st.column_config.NumberColumn(
                        "Rows Scanned",
                        format="%d",
                    ),
                    "country": st.column_config.TextColumn("Country"),
                    "asn_name": st.column_config.TextColumn("ASN / Carrier"),
                    "risk_score": st.column_config.ProgressColumn(
                        "Risk Score",
                        min_value=0,
                        max_value=100,
                        format="%f",
                    ),
                },
            )

            # ── Summary metrics ──────────────────────────────────────────
            total_sessions = len(records)
            critical_count = sum(1 for r in records if (r.get("risk_score") or 0) >= 65)
            scores = [r.get("risk_score") or 0 for r in records]
            avg_score = round(sum(scores) / len(scores), 1) if scores else 0

            st.markdown(
                f"""
                <div class="metric-row">
                    <div class="metric-card">
                        <div class="val">{total_sessions}</div>
                        <div class="lbl">Sessions Scanned</div>
                    </div>
                    <div class="metric-card danger">
                        <div class="val">{critical_count}</div>
                        <div class="lbl">Critical Alerts (&ge;65)</div>
                    </div>
                    <div class="metric-card warn">
                        <div class="val">{avg_score}</div>
                        <div class="lbl">Avg Risk Score</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div style="color:#8b949e; padding:2rem; text-align:center;">'
                '⬆️ Click <strong>Run Threat Scan</strong> to pull live telemetry from Snowflake.'
                '</div>',
                unsafe_allow_html=True,
            )

    # ════════════════════════════════════════════════════════════════════════
    # RIGHT COLUMN — 🤖 Cortex AI SecOps Engine
    # ════════════════════════════════════════════════════════════════════════
    with col_right:
        st.markdown(
            '<div class="section-title">🤖 Cortex AI SecOps Engine</div>',
            unsafe_allow_html=True,
        )

        records = st.session_state.get("records", [])

        if not records:
            st.markdown(
                '<div style="color:#8b949e; padding:2rem; text-align:center;">'
                '⬅️ Run a Threat Scan first to enable AI analysis.'
                '</div>',
                unsafe_allow_html=True,
            )
        else:
            # Auto-select highest risk session & serialise all fields
            top_event_raw = max(records, key=lambda r: r.get("risk_score") or 0)
            top_event     = _serialize_row(top_event_raw)
            top_score     = top_event.get("risk_score") or 0

            # ── Critical warning banner ──────────────────────────────────
            if top_score >= 65:
                st.markdown(
                    f'<div class="alert-critical">'
                    f'🚨 CRITICAL THREAT DETECTED: Risk Score {top_score}/100'
                    f'</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.info(
                    f"ℹ️ Highest risk score: **{top_score}/100** — below critical threshold (65).",
                    icon="🔵",
                )

            # ── Threat Dossier ─────────────────────────────────────────────
            st.markdown(
                '<div class="section-title" style="margin-top:.5rem;">'
                '📋 Threat Dossier — Highest-Risk Actor</div>',
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
                <div class=\"dossier\">
                    <div class=\"dossier-row\">
                        <div><div class=\"dossier-label\">Origin Country</div>
                             <div class=\"dossier-value highlight\">{top_event.get('country', 'Unknown')}</div></div>
                        <div><div class=\"dossier-label\">Rogue IP Address</div>
                             <div class=\"dossier-value ip\">{top_event.get('client_ip', '—')}</div></div>
                    </div>
                    <div class=\"dossier-row\">
                        <div><div class=\"dossier-label\">ASN Infrastructure</div>
                             <div class=\"dossier-value\">{top_event.get('asn_name', 'Unknown')}</div></div>
                        <div><div class=\"dossier-label\">Rows Exfiltrated</div>
                             <div class=\"dossier-value\" style=\"color:#f85149;font-weight:800;\">{rows_fmt}</div></div>
                    </div>
                    <hr class=\"dossier-divider\">
                    <div class=\"dossier-row full\">
                        <div><div class=\"dossier-label\">Abused Role</div>
                             <div class=\"dossier-value role\">{top_event.get('role_used', '—')}</div></div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            query_preview = str(top_event.get("query_text") or "— no query captured —")
            st.markdown(
                '<div class="dossier-label" style="margin-bottom:.35rem;">🔎 Captured Query</div>',
                unsafe_allow_html=True,
            )
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
                    with st.spinner(
                        "Calling SNOWFLAKE.CORTEX.COMPLETE('llama3.1-8b', …) inside warehouse…"
                    ):
                        ai_text = run_cortex_ai(conn, top_event)
                    st.session_state["ai_response"] = ai_text
            if "ai_response" in st.session_state:
                st.markdown("---")
                st.markdown(
                    '<div class="section-title">🧠 Llama 3.1 Incident Report</div>',
                    unsafe_allow_html=True,
                )
                st.markdown(st.session_state["ai_response"])


# ── Entrypoint ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
