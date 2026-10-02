# 🛡️ SWarden: Zero-Trust Threat & Exfiltration Auditor

## Overview
A Security Information and Event Management (SIEM) dashboard built for detecting session hijacking and data exfiltration in real-time. SWarden intercepts anomalous activity by mapping query telemetry to real-time risk scores, offering proactive threat containment within Snowflake environments.

## Core Features
* **Zero-Trust Validation:** Cross-references active session IPs against the IPinfo Lite Marketplace dataset to detect geographic anomalies and cloud-hosting infrastructure (ASN) abuse.
* **Exfiltration Detection:** Calculates real-time threat scores based on network intent and row-scanned thresholds.
* **Cortex AI Copilot:** Natural Language-to-SQL engine powered natively by open-weight Llama 3.1 within Snowflake Cortex.
* **Automated Remediation:** Instantly generates precise SQL commands to abort hijacked sessions and revoke user privileges.

## Architecture & Tech Stack
* **Frontend:** Streamlit with native Snowsight styling.
* **Database & Pipeline:** Snowflake SQL generated via Cortex Code (CoCo) and Marketplace data.
* **AI Engine:** Snowflake Cortex (`llama3.1-8b`).
* **Security:** Enterprise-grade RSA Key-Pair Authentication via the Python connector.
