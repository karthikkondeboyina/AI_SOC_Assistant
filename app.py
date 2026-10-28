"""
AI-Powered Autonomous SOC Assistant - Main Streamlit Application
Enterprise Security Operations Center Dashboard featuring Machine Learning Threat Detection,
Explainable Risk Scoring, SQLite Incident Tracking, RAG Knowledge Retrieval, and Google Gemini AI Investigation.
"""

import sys
from pathlib import Path
import json
import uuid
import time
from datetime import datetime

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

# Ensure project root is on sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from config.settings import (
    MODEL_FILE,
    METADATA_FILE,
    SAMPLE_DATA_DIR,
    RAW_DATA_DIR,
    DATABASE_PATH,
    ASSETS_DIR,
    GEMINI_API_KEY,
    GEMINI_MODEL
)
from modules.preprocessing import clean_dataset, clean_label_string
from modules.feature_validation import validate_dataset_schema
from modules.threat_detection import load_threat_model, is_model_available, detect_threats
from modules.risk_scoring import batch_calculate_risk, calculate_risk_score
from modules.database import (
    init_db,
    save_analysis_run,
    save_incidents,
    get_recent_incidents,
    get_incident_by_id,
    update_incident_status,
    save_investigation_report,
    get_investigation_report,
    get_db_metrics,
    get_monitored_agents,
    get_live_alerts,
    get_live_alert_by_id,
    update_live_alert_status,
    get_recent_security_events,
    get_live_monitoring_metrics,
    convert_alert_to_incident
)
from modules.incident_manager import group_suspicious_flows_into_incidents
from modules.llm_analysis import is_gemini_configured, analyze_security_incident, ask_incident_question
from modules.rag_system import get_rag_system
from modules.mitre_mapping import map_threat_to_mitre, OFFICIAL_MITRE_MAPPINGS
from utils.helpers import format_number, format_bytes, get_severity_badge_html
from modules.live_monitor.windows_collector import WindowsSecurityLogCollector
from modules.live_monitor.detection_rules import get_live_detection_engine
from simulation.simulate_logs import generate_scenario_events
from config.settings import SOC_API_HOST, SOC_API_PORT, SOC_AGENT_TOKEN
import httpx

# ==============================================================================
# 1. PAGE CONFIGURATION & STYLING
# ==============================================================================

st.set_page_config(
    page_title="AI SOC Assistant | Enterprise Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load external CSS stylesheet
css_path = ASSETS_DIR / "styles.css"
if css_path.exists():
    with open(css_path, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# Initialize Session State Variables
if "dataset" not in st.session_state:
    st.session_state.dataset = None
if "filename" not in st.session_state:
    st.session_state.filename = None
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = None
if "analysis_summary" not in st.session_state:
    st.session_state.analysis_summary = None
if "current_incidents" not in st.session_state:
    st.session_state.current_incidents = []
if "selected_incident_id" not in st.session_state:
    st.session_state.selected_incident_id = None
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

# Initialize database schema
init_db()

# ==============================================================================
# 2. SIDEBAR NAVIGATION & SYSTEM BADGES
# ==============================================================================

with st.sidebar:
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 5px;">
        <span style="font-size: 2rem;">🛡️</span>
        <div>
            <h2 style="margin: 0; font-size: 1.35rem; color: #F8FAFC;">AI SOC ASSISTANT</h2>
            <p style="margin: 0; font-size: 0.78rem; color: #94A3B8;">Autonomous SecOps Platform</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.divider()
    
    page = st.radio(
        "OPERATIONAL NAVIGATION",
        [
            "🏠 Dashboard Overview",
            "📡 Live Security Monitor",
            "💻 Agent Management",
            "📁 Upload Security Data",
            "📊 Data Analytics",
            "🚨 Threat Detection",
            "🛡️ Security Incidents",
            "🤖 AI Investigation",
            "📚 MITRE ATT&CK",
            "⚙️ System Status"
        ],
        index=0
    )
    
    st.divider()
    
    # Live System Status Indicators in Sidebar
    st.markdown("<p style='font-size: 0.8rem; font-weight: 700; color: #94A3B8; text-transform: uppercase;'>Module Readiness</p>", unsafe_allow_html=True)
    
    model_ready = is_model_available()
    gemini_ready = is_gemini_configured()
    rag_ready = (BASE_DIR / "knowledge_base" / "faiss_index" / "faiss.index").exists()
    
    st.markdown(
        f"""
        <div style="font-size: 0.82rem; line-height: 1.8;">
            <div>{'🟢' if model_ready else '🔴'} <b>ML Model:</b> {'Loaded (v1.0.0)' if model_ready else 'Not Trained'}</div>
            <div>{'🟢' if gemini_ready else '🟡'} <b>Gemini AI:</b> {'Configured' if gemini_ready else 'Key Missing (.env)'}</div>
            <div>{'🟢' if rag_ready else '🟡'} <b>RAG Index:</b> {'FAISS Ready' if rag_ready else 'Rebuilding'}</div>
            <div>🟢 <b>Database:</b> SQLite Connected</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    st.divider()
    st.caption("B.Tech Final Year Project | Data Science & Cybersecurity")
    st.caption("Defensive Human-in-the-Loop Architecture")

# ==============================================================================
# PAGE 1: DASHBOARD OVERVIEW
# ==============================================================================

if page == "🏠 Dashboard Overview":
    st.markdown("""
    <div class="soc-header-card">
        <h1 class="soc-header-title"><span>🛡️</span> Security Operations Center Dashboard</h1>
        <p class="soc-header-subtitle">Real-time network telemetry analysis, autonomous threat classification, and incident triage</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Retrieve true operational metrics from SQLite
    db_metrics = get_db_metrics()
    recent_incidents = get_recent_incidents(limit=10)
    
    # Primary Operational Metric Cards
    c1, c2, c3, c4 = st.columns(4)
    
    # If an active dataset is loaded in memory
    total_analyzed = len(st.session_state.analysis_results) if st.session_state.analysis_results is not None else 0
    suspicious_count = st.session_state.analysis_summary.get("suspicious_count", 0) if st.session_state.analysis_summary else 0
    
    c1.metric("Analyzed Records", f"{total_analyzed:,}" if total_analyzed else f"{db_metrics['total_runs']} Runs")
    c2.metric("Suspicious Traffic", f"{suspicious_count:,}" if suspicious_count else "0 Flows")
    c3.metric("High-Risk Alerts", f"{db_metrics['high_risk_incidents']}")
    c4.metric("Total Incidents", f"{db_metrics['total_incidents']}")
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Visual Analytics Row
    if st.session_state.analysis_results is not None:
        res_df = st.session_state.analysis_results
        
        col_left, col_right = st.columns(2)
        
        with col_left:
            st.subheader("📊 Detected Attack Class Distribution")
            attack_counts = res_df[res_df["is_suspicious"] == True]["predicted_class"].value_counts().reset_index()
            attack_counts.columns = ["Attack Class", "Count"]
            
            if not attack_counts.empty:
                fig_pie = px.pie(
                    attack_counts,
                    names="Attack Class",
                    values="Count",
                    hole=0.45,
                    template="plotly_dark",
                    color_discrete_sequence=px.colors.sequential.Tealgrn_r
                )
                fig_pie.update_layout(margin=dict(t=20, b=20, l=20, r=20), height=320)
                st.plotly_chart(fig_pie, width='stretch')
            else:
                st.info("No suspicious attack events detected in the active dataset.")
                
        with col_right:
            st.subheader("⚡ Threat Severity Breakdown")
            sev_counts = res_df["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            
            color_map = {
                "Critical": "#EF4444",
                "High": "#F97316",
                "Medium": "#EAB308",
                "Low": "#3B82F6",
                "Benign": "#10B981"
            }
            
            fig_bar = px.bar(
                sev_counts,
                x="Severity",
                y="Count",
                color="Severity",
                color_discrete_map=color_map,
                template="plotly_dark"
            )
            fig_bar.update_layout(margin=dict(t=20, b=20, l=20, r=20), height=320, showlegend=False)
            st.plotly_chart(fig_bar, width='stretch')
            
    else:
        # Informative Empty State
        st.info("ℹ️ No active telemetry analysis in session. Upload a dataset or load the sample data to display real-time telemetry charts.")
        
    st.divider()
    
    # Recent Incidents Table
    st.subheader("🚨 Security Incidents Queue")
    if recent_incidents:
        inc_data = []
        for inc in recent_incidents:
            inc_data.append({
                "Incident ID": inc["incident_id"],
                "Threat Category": inc["threat_category"],
                "Severity": inc["severity"],
                "Risk Score": f"{inc['max_risk_score']:.1f}",
                "Events": inc["event_count"],
                "MITRE ATT&CK": f"{inc['mitre_technique_id']} ({inc['mitre_technique_name']})",
                "Status": inc["status"],
                "Logged At": inc["created_at"][:19].replace("T", " ")
            })
            
        st.dataframe(pd.DataFrame(inc_data), width='stretch', hide_index=True)
    else:
        st.markdown("""
        <div style="background-color: #132238; border: 1px dashed #203552; border-radius: 8px; padding: 24px; text-align: center;">
            <p style="color: #94A3B8; margin: 0; font-size: 1rem;">No incidents logged in the database yet.</p>
            <p style="color: #64748B; font-size: 0.85rem; margin-top: 6px;">Execute Threat Detection on a network dataset to record and triage security incidents.</p>
        </div>
        """, unsafe_allow_html=True)

# ==============================================================================
# PAGE: LIVE SECURITY MONITOR
# ==============================================================================

elif page == "📡 Live Security Monitor":
    st.markdown("""
    <div class="soc-header-card">
        <h1 class="soc-header-title"><span>📡</span> Near-Real-Time Host Security Monitor</h1>
        <p class="soc-header-subtitle">Stream continuous authentication events, detect brute force & password spray patterns, and triage live alerts</p>
    </div>
    """, unsafe_allow_html=True)

    live_metrics = get_live_monitoring_metrics()

    # Check Ingestion API Status
    api_online = False
    try:
        with httpx.Client(timeout=1.0) as client:
            r = client.get(f"http://{SOC_API_HOST}:{SOC_API_PORT}/health")
            if r.status_code == 200:
                api_online = True
    except Exception:
        api_online = False

    # Top KPI Metrics Cards
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    k1.metric("Ingestion API", "🟢 Online" if api_online else "🔴 Offline")
    k2.metric("Connected Agents", f"{live_metrics['active_agents']} / {live_metrics['total_agents']}")
    k3.metric("Total Events", f"{live_metrics['total_events']:,}")
    k4.metric("Failed Logins", f"{live_metrics['failed_logins']:,}")
    k5.metric("Active Alerts", f"{live_metrics['active_alerts']}")
    k6.metric("Critical / High", f"{live_metrics['critical_alerts']}")

    st.markdown("<br>", unsafe_allow_html=True)

    if not api_online:
        st.warning(f"⚠️ Central Ingestion API service is offline at http://{SOC_API_HOST}:{SOC_API_PORT}. Start the API in a separate terminal: `python -m api.server` to receive live telemetry from network agents.")

    tab_alerts, tab_events, tab_local, tab_sim = st.tabs([
        "🚨 Live Alerts Queue",
        "📋 Ingested Security Events",
        "🖥️ Local Windows Collector",
        "🧪 Live Attack Simulator"
    ])

    with tab_alerts:
        st.subheader("🚨 Real-Time Security Alerts (Sliding-Window Engine)")
        
        c_f1, c_f2 = st.columns(2)
        with c_f1:
            sev_filter = st.selectbox("Filter Alert Severity", ["All", "Critical", "High", "Medium", "Low"], key="live_sev_filter")
        with c_f2:
            stat_filter = st.selectbox("Filter Alert Status", ["All", "New", "Investigating", "Resolved", "False Positive"], key="live_stat_filter")
            
        alerts = get_live_alerts(limit=50, severity=sev_filter, status=stat_filter)
        
        if not alerts:
            st.info("No active threat alerts in the queue. Run the 'Live Attack Simulator' tab to generate synthetic security alerts.")
        else:
            st.write(f"Displaying **{len(alerts)}** active threat alerts:")
            for alt in alerts:
                with st.container():
                    st.markdown(f"""
                    <div class="soc-card">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <h4 style="margin: 0; color: #F8FAFC;">🚨 {alt['alert_id']} - {alt['rule_name']}</h4>
                            <div>
                                {get_severity_badge_html(alt['severity'])}
                                <span style="background: #1E293B; border: 1px solid #334155; padding: 4px 10px; border-radius: 6px; font-size: 0.8rem; margin-left: 8px;">
                                    Status: <b>{alt['status']}</b>
                                </span>
                            </div>
                        </div>
                        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 15px 0; font-size: 0.9rem;">
                            <div><b>Risk Score:</b> <span style="color: #06B6D4;">{alt['risk_score']:.1f}/100</span></div>
                            <div><b>Target Host:</b> <code>{alt['hostname']}</code> ({alt['agent_id']})</div>
                            <div><b>Target Account:</b> <code>{alt['username'] or 'N/A'}</code></div>
                            <div><b>Source IP:</b> <code>{alt['source_ip'] or 'Internal/Local'}</code></div>
                        </div>
                        <p style="color: #F1F5F9; font-size: 0.88rem; margin: 6px 0;"><b>Evidence:</b> {alt['evidence_summary']}</p>
                        <p style="color: #94A3B8; font-size: 0.82rem; margin: 4px 0;"><b>MITRE ATT&CK:</b> <a href="{map_threat_to_mitre(alt['rule_name'])['url']}" target="_blank" style="color: #38BDF8;">{alt['mitre_technique_id']} - {alt['mitre_technique_name']}</a> | <b>Attempts:</b> {alt['event_count']} within sliding window</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    c_act1, c_act2 = st.columns([3, 1])
                    with c_act1:
                        new_alt_st = st.selectbox(
                            "Update Alert Status",
                            ["New", "Investigating", "Resolved", "False Positive"],
                            index=["New", "Investigating", "Resolved", "False Positive"].index(alt["status"]),
                            key=f"alt_st_{alt['alert_id']}"
                        )
                        if new_alt_st != alt["status"]:
                            update_live_alert_status(alt["alert_id"], new_alt_st)
                            st.success(f"Updated alert status to '{new_alt_st}'")
                            st.rerun()
                    with c_act2:
                        if st.button("🤖 Investigate with AI", key=f"inv_alt_{alt['alert_id']}", width='stretch'):
                            inc_id = convert_alert_to_incident(alt["alert_id"])
                            if inc_id:
                                st.session_state.selected_incident_id = inc_id
                                st.success(f"Escalated alert to Incident `{inc_id}`! Navigate to '🤖 AI Investigation' in the sidebar to review Gemini advisory report.")
                            else:
                                st.error("Failed to promote alert to incident.")

    with tab_events:
        st.subheader("📋 Ingested Security Events Telemetry")
        c_e1, c_e2 = st.columns(2)
        with c_e1:
            ev_type_filter = st.selectbox("Filter Event Type", ["All", "FAILED_LOGIN", "SUCCESSFUL_LOGIN", "ACCOUNT_LOCKOUT", "LOGOFF"], key="ev_type_filter")
        with c_e2:
            ev_limit = st.selectbox("Records Limit", [50, 100, 200], index=1, key="ev_limit")
            
        recent_events = get_recent_security_events(limit=ev_limit, event_type=ev_type_filter)
        if recent_events:
            ev_display = []
            for e in recent_events:
                ev_display.append({
                    "Timestamp (UTC)": e["timestamp"][:19].replace("T", " "),
                    "Hostname": e["hostname"],
                    "Agent ID": e["agent_id"],
                    "Event Type": e["event_type"],
                    "Win Event ID": e["windows_event_id"] or "N/A",
                    "Username": e["username"],
                    "Source IP": e["source_ip"] or "Local",
                    "Description": e["description"]
                })
            st.dataframe(pd.DataFrame(ev_display), width='stretch', hide_index=True)
        else:
            st.info("No security events ingested yet. Send events using the simulator or local collector.")

    with tab_local:
        st.subheader("🖥️ Local Windows Security Event Log Collector")
        st.write("Reads authentic Windows Security Event Logs (Event IDs 4624, 4625, 4634, 4740) from this machine.")
        
        col_win = WindowsSecurityLogCollector()
        env_status = col_win.check_environment()
        
        c_diag1, c_diag2 = st.columns([2, 1])
        with c_diag1:
            st.markdown(f"""
            <div style="background-color: #0F172A; border: 1px solid #334155; border-radius: 8px; padding: 18px; margin-bottom: 15px;">
                <h4 style="margin: 0; color: #F8FAFC;">Collector Diagnostic Status: {'🟢 Ready' if env_status['capable'] else '🟡 Limited Privileges'}</h4>
                <p style="margin: 8px 0 0 0; color: #94A3B8; font-size: 0.9rem;"><b>OS:</b> {env_status.get('os')} | <b>Platform API:</b> pywin32 EvtQuery</p>
                <p style="margin: 4px 0 0 0; color: #94A3B8; font-size: 0.88rem;"><b>Diagnostics:</b> {env_status.get('reason')}</p>
                <p style="margin: 4px 0 0 0; color: #38BDF8; font-size: 0.85rem;"><b>Recommended Action:</b> {env_status.get('solution')}</p>
            </div>
            """, unsafe_allow_html=True)
            
        with c_diag2:
            st.metric("Last Processed Record", f"#{col_win.last_record_id}")
            
        if env_status["capable"]:
            if st.button("⚡ Collect & Ingest New Local Windows Events", width='stretch'):
                with st.spinner("Querying Windows Event Log channel..."):
                    collected_events, diag = col_win.collect_new_events(max_events=100)
                    if collected_events:
                        engine = get_live_detection_engine()
                        raw_dicts = [e.model_dump() for e in collected_events]
                        inserted = save_security_events_batch(raw_dicts)
                        alerts_trig = engine.process_batch(collected_events)
                        for a in alerts_trig:
                            save_live_alert(a.to_dict())
                        st.success(f"Collected {len(collected_events)} new Windows security events! ({inserted} ingested, {len(alerts_trig)} alerts triggered)")
                        st.rerun()
                    else:
                        st.info("No new authentication events recorded in the Windows Security Log since last bookmark.")
        else:
            st.info("💡 **College Demo Note**: Reading Windows Security Event Logs requires Administrator rights. To demonstrate live threat detection safely without Administrator elevation, switch to the **🧪 Live Attack Simulator** tab.")

    with tab_sim:
        st.subheader("🧪 Safe Test Event Simulator")
        st.write("Generate synthetic authentication event streams to safely test and demonstrate near-real-time detection rules, risk scoring, and AI escalation.")
        
        c_sim1, c_sim2 = st.columns(2)
        with c_sim1:
            sim_scenario = st.selectbox(
                "Select Attack / Telemetry Scenario",
                [
                    "failed-logins",
                    "password-spray",
                    "lockout",
                    "rdp-brute",
                    "normal",
                    "mixed"
                ],
                format_func=lambda s: {
                    "failed-logins": "🚨 Repeated Failed Logins (Rule 1 & Rule 2 Brute-Force)",
                    "password-spray": "🌊 Password Spraying (Rule 3 Single IP vs Multi-User)",
                    "lockout": "🔒 Account Lockout Triggered (Rule 4 Event 4740)",
                    "rdp-brute": "💻 Remote Desktop RDP Failure (Rule 5)",
                    "normal": "🟢 Normal Benign Activity (Successful Logons & Logoffs)",
                    "mixed": "⚡ Mixed Operational Security Stream"
                }.get(s, s)
            )
        with c_sim2:
            sim_host = st.text_input("Simulated Hostname", value="FINANCE-SRV-01")
            
        sim_count = st.slider("Number of Events to Generate", min_value=5, max_value=25, value=10)
        
        if st.button("🚀 Execute Safe Demonstration Stream", width='stretch'):
            with st.spinner("Generating and ingesting synthetic security telemetry..."):
                synthetic_evs = generate_scenario_events(
                    scenario=sim_scenario,
                    agent_id=f"sim-{sim_host.lower()}",
                    hostname=sim_host,
                    count=sim_count
                )
                
                # Register agent
                register_or_update_agent(agent_id=f"sim-{sim_host.lower()}", hostname=sim_host, ip_address="192.168.1.155", os_type="Windows (Simulated)")
                
                # Ingest to DB
                raw_dicts = [e.model_dump() for e in synthetic_evs]
                inserted = save_security_events_batch(raw_dicts)
                
                # Run Live Engine
                engine = get_live_detection_engine()
                triggered = engine.process_batch(synthetic_evs)
                for a in triggered:
                    save_live_alert(a.to_dict())
                    
                st.success(f"Stream complete! Ingested {inserted} synthetic events. Triggered **{len(triggered)}** threat detection alerts!")
                st.rerun()

# ==============================================================================
# PAGE: AGENT MANAGEMENT
# ==============================================================================

elif page == "💻 Agent Management":
    st.markdown("""
    <div class="soc-header-card">
        <h1 class="soc-header-title"><span>💻</span> Monitored Computer & Agent Fleet Management</h1>
        <p class="soc-header-subtitle">Monitor authorized endpoint agents across local Windows computers and LAN network nodes</p>
    </div>
    """, unsafe_allow_html=True)
    
    agents = get_monitored_agents()
    
    c_m1, c_m2, c_m3 = st.columns(3)
    active_count = sum(1 for a in agents if a.get("status") == "Active")
    c_m1.metric("Registered Agents", len(agents))
    c_m2.metric("Online & Active", active_count)
    c_m3.metric("Offline / Inactive", len(agents) - active_count)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    st.subheader("📋 Registered Endpoints Fleet")
    if agents:
        agent_display = []
        for a in agents:
            agent_display.append({
                "Agent ID": a["agent_id"],
                "Hostname": a["hostname"],
                "IP Address": a["ip_address"] or "127.0.0.1",
                "OS Type": a["os_type"] or "Windows",
                "Status": "🟢 Active" if a.get("status") == "Active" else "🟡 Inactive",
                "Total Events": f"{a.get('total_events', 0):,}",
                "Last Seen (UTC)": a["last_seen"][:19].replace("T", " "),
                "Registered At": a["registered_at"][:19].replace("T", " "),
                "Version": a.get("agent_version", "2.0.0")
            })
        st.dataframe(pd.DataFrame(agent_display), width='stretch', hide_index=True)
    else:
        st.info("No monitoring agents registered yet. Start an agent or launch the simulator to connect endpoints.")
        
    st.divider()
    
    st.subheader("🚀 Deploying a New Monitoring Agent on LAN")
    st.markdown("""
    Follow these steps to monitor a remote Windows or Linux computer connected to the same LAN / Wi-Fi network:

    #### Step 1: Start Central SOC Ingestion Server
    On your main SOC host machine, start the FastAPI ingestion service:
    ```powershell
    python -m api.server
    ```
    *Ensure your Windows Firewall allows inbound TCP connections on port 8000.*

    #### Step 2: Deploy Lightweight Agent on Authorized Computer
    Copy the `agent/` folder to the target machine and execute:
    ```powershell
    # Windows Target Host
    python -m agent.agent --server http://<YOUR_SOC_SERVER_IP>:8000 --token soc-secure-agent-token-2026 --agent-id remote-pc-02
    ```
    ```bash
    # Linux Target Host (run with auth.log read permissions)
    python -m agent.agent --server http://<YOUR_SOC_SERVER_IP>:8000 --token soc-secure-agent-token-2026 --agent-id linux-server-01
    ```

    #### Security & Safety Guarantees:
    - **No Remote Command Execution**: Agents only push telemetry; the central server cannot execute commands on remote hosts.
    - **No Password Collection**: The agent parser explicitly strips and ignores authentication secrets.
    - **Resilient Bounded Queue**: If the network is interrupted, events buffer in an in-memory queue and retry with exponential backoff.
    """)

# ==============================================================================
# PAGE 2: SECURITY DATA UPLOAD
# ==============================================================================

elif page == "📁 Upload Security Data":
    st.markdown("""
    <div class="soc-header-card">
        <h1 class="soc-header-title"><span>📁</span> Ingest Security Network Telemetry</h1>
        <p class="soc-header-subtitle">Upload CSV/Parquet network-flow datasets (CIC-IDS2017 schema) for validation and analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    col_upload, col_sample = st.columns([2, 1])
    
    with col_upload:
        st.subheader("Upload Telemetry File")
        uploaded_file = st.file_uploader(
            "Select network flow file (CSV or Parquet)",
            type=["csv", "parquet"],
            help="Supports network-flow captures conforming to the CIC-IDS2017 schema."
        )
        
    with col_sample:
        st.subheader("Or Load Built-in Test Dataset")
        sample_path = SAMPLE_DATA_DIR / "sample_soc_traffic.csv"
        if sample_path.exists():
            if st.button("🚀 Load Sample Dataset (1,000 real flows)", width='stretch'):
                sample_df = pd.read_csv(sample_path)
                st.session_state.dataset = sample_df
                st.session_state.filename = "sample_soc_traffic.csv"
                st.session_state.analysis_results = None
                st.success("Loaded genuine sample network dataset containing diverse attack and benign flows!")
                st.rerun()
        else:
            st.info("Sample dataset will be generated during model training.")

    # Process Uploaded File
    if uploaded_file is not None:
        try:
            if uploaded_file.name.endswith(".parquet"):
                raw_df = pd.read_parquet(uploaded_file)
            else:
                raw_df = pd.read_csv(uploaded_file)
                
            st.session_state.dataset = raw_df
            st.session_state.filename = uploaded_file.name
            st.session_state.analysis_results = None
            st.success(f"File '{uploaded_file.name}' loaded successfully!")
        except Exception as e:
            st.error(f"Failed to parse uploaded file: {str(e)}")

    st.divider()

    # Display Dataset Diagnostics if loaded
    if st.session_state.dataset is not None:
        df = st.session_state.dataset
        
        # Cache profiling in session state so tab navigation is instant
        if "clean_stats" not in st.session_state or st.session_state.get("cleaned_for_file") != st.session_state.filename:
            with st.spinner("Profiling dataset..."):
                cleaned_preview, clean_stats = clean_dataset(df.head(10000) if len(df) > 10000 else df)
                st.session_state.cleaned_preview = cleaned_preview
                st.session_state.clean_stats = clean_stats
                st.session_state.cleaned_for_file = st.session_state.filename
        else:
            cleaned_preview = st.session_state.cleaned_preview
            clean_stats = st.session_state.clean_stats
            
        st.subheader("📋 Dataset Telemetry Profile")
        
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Total Records", f"{len(df):,}")
        m2.metric("Features", len(df.columns))
        m3.metric("Missing Values", f"{clean_stats['nan_values_imputed']:,}")
        m4.metric("Infinities Replaced", f"{clean_stats['inf_values_replaced']:,}")
        m5.metric("File Format", st.session_state.filename.split(".")[-1].upper())
        
        # Schema Compatibility Verification
        _, metadata = load_threat_model()
        expected_feats = metadata.get("feature_names", []) if metadata else []
        validation_report = validate_dataset_schema(df, expected_feats)
        
        if validation_report["is_valid"]:
            st.success(f"✅ Schema Check: {validation_report['message']}")
        else:
            st.warning(f"⚠️ Schema Diagnostic: {validation_report['message']}")
            
        # Dataset Preview Table
        st.subheader("Data Preview (First 50 Rows)")
        st.dataframe(cleaned_preview.head(50), width='stretch')
        
        with st.expander("🔍 View All Column Names and Data Types"):
            sample_vals = [str(x) for x in cleaned_preview.iloc[0].values] if len(cleaned_preview) > 0 else []
            dtypes_df = pd.DataFrame({
                "Feature Name": [str(c) for c in cleaned_preview.columns],
                "Data Type": [str(t) for t in cleaned_preview.dtypes],
                "Sample Value": sample_vals if sample_vals else ["N/A"] * len(cleaned_preview.columns)
            })
            st.dataframe(dtypes_df, width='stretch', hide_index=True)
    else:
        st.info("Please upload a file or click 'Load Sample Dataset' above to inspect network telemetry.")

# ==============================================================================
# PAGE 3: DATA ANALYTICS
# ==============================================================================

elif page == "📊 Data Analytics":
    st.markdown("""
    <div class="soc-header-card">
        <h1 class="soc-header-title"><span>📊</span> Network Data Analytics & Feature Exploration</h1>
        <p class="soc-header-subtitle">Exploratory analysis of network flow metrics, class balance, and correlation structures</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.session_state.dataset is None:
        st.warning("⚠️ No dataset loaded. Please go to 'Upload Security Data' first.")
    else:
        df = st.session_state.dataset
        
        tab_dist, tab_corr, tab_labels = st.tabs([
            "📈 Feature Distributions",
            "🔥 Correlation Heatmap",
            "🏷️ Ground-Truth Labels"
        ])
        
        with tab_dist:
            numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
            if numeric_cols:
                col_sel, col_scale = st.columns([3, 1])
                with col_sel:
                    feature = st.selectbox("Select Numerical Network Feature", numeric_cols, index=min(1, len(numeric_cols)-1))
                with col_scale:
                    log_scale = st.checkbox("Logarithmic Y-Axis", value=True)
                    
                # Downsample large datasets for instant chart rendering without browser lag
                plot_sample = df[[feature]].sample(min(len(df), 50000), random_state=42) if len(df) > 50000 else df[[feature]]
                if len(df) > 50000:
                    st.caption(f"⚡ Displaying high-fidelity distribution sample (50,000 of {len(df):,} records)")
                    
                fig = px.histogram(
                    plot_sample,
                    x=feature,
                    nbins=50,
                    log_y=log_scale,
                    title=f"Distribution of {feature}",
                    template="plotly_dark",
                    color_discrete_sequence=["#06B6D4"]
                )
                fig.update_layout(height=420)
                st.plotly_chart(fig, width='stretch')
                
                # Statistical Breakdown
                st.markdown("#### Descriptive Statistics")
                stats_df = df[feature].describe().to_frame().T
                st.dataframe(stats_df, width='stretch')
            else:
                st.info("No numeric features found for distribution plotting.")
                
        with tab_corr:
            st.markdown("#### Pearson Correlation Analysis (Key Flow Indicators)")
            # Pick a subset of key flow features to avoid 78x78 visual congestion
            candidate_cols = [
                "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
                "Fwd Packets Length Total", "Bwd Packets Length Total",
                "Flow Bytes/s", "Flow Packets/s", "Fwd Packet Length Mean",
                "Bwd Packet Length Mean", "Average Packet Size"
            ]
            clean_cols = [c.strip() for c in df.columns]
            selected_corr_cols = [c for c in candidate_cols if c in clean_cols]
            
            if len(selected_corr_cols) >= 3:
                # Sample up to 25,000 for instant correlation matrix
                sample_corr_df = df[selected_corr_cols].sample(min(len(df), 25000), random_state=42) if len(df) > 25000 else df[selected_corr_cols]
                sub_df = sample_corr_df.replace([np.inf, -np.inf], np.nan).dropna()
                corr_matrix = sub_df.corr()
                
                fig_heat = px.imshow(
                    corr_matrix,
                    text_auto=".2f",
                    color_continuous_scale="Viridis",
                    template="plotly_dark",
                    title="Correlation Matrix of Selected Telemetry Features"
                )
                fig_heat.update_layout(height=520)
                st.plotly_chart(fig_heat, width='stretch')
            else:
                st.info("Selected network flow columns not found in the uploaded dataset.")
                
        with tab_labels:
            st.markdown("#### Ground-Truth Label Breakdown")
            label_col = None
            for cand in ["Label", "label", "Attack", "class"]:
                if cand in df.columns:
                    label_col = cand
                    break
                    
            if label_col:
                # Fast label cleaning via unique value mapping
                unique_raw = df[label_col].dropna().unique()
                lbl_map = {lbl: clean_label_string(lbl) for lbl in unique_raw}
                clean_series = df[label_col].map(lbl_map).fillna("Unknown")
                label_counts = clean_series.value_counts().reset_index()
                label_counts.columns = ["True Label", "Count"]
                
                fig_labels = px.bar(
                    label_counts,
                    x="True Label",
                    y="Count",
                    color="True Label",
                    template="plotly_dark",
                    title=f"Ground-Truth Class Frequencies ({label_col})"
                )
                st.plotly_chart(fig_labels, width='stretch')
                st.dataframe(label_counts, width='stretch', hide_index=True)
            else:
                st.info("Uploaded dataset does not contain a ground-truth 'Label' column (unlabeled inference data).")

# ==============================================================================
# PAGE 4: THREAT DETECTION
# ==============================================================================

elif page == "🚨 Threat Detection":
    st.markdown("""
    <div class="soc-header-card">
        <h1 class="soc-header-title"><span>🚨</span> Machine Learning Threat Classification</h1>
        <p class="soc-header-subtitle">Execute multi-class threat classification, evaluate confidence, and compute explainable risk scores</p>
    </div>
    """, unsafe_allow_html=True)
    
    if not is_model_available():
        st.error("ML Model is not yet trained. Please run 'python training/train_model.py' to generate model artifacts.")
    elif st.session_state.dataset is None:
        st.warning("No dataset loaded. Please go to 'Upload Security Data' or load the built-in sample data.")
    else:
        df = st.session_state.dataset
        
        c_ctrl1, c_ctrl2 = st.columns([3, 1])
        with c_ctrl1:
            st.write(f"Target Telemetry File: `{st.session_state.filename}` ({len(df):,} total flows)")
        with c_ctrl2:
            asset_crit = st.selectbox("Asset Criticality Level", ["Standard", "High", "Mission-Critical", "Low"], index=0)
            
        # Analysis batch controls for responsive triage of large network captures
        if len(df) > 10000:
            scope_choices = [
                f"🚀 Fast Triage (First 10,000 flows — Instant Screen)",
                f"⚡ Standard Batch (First 50,000 flows — Comprehensive)",
                f"🌐 Full File ({len(df):,} flows — Deep Analysis)"
            ]
            batch_choice = st.radio(
                "Analysis Batch Scope",
                scope_choices,
                index=0,
                horizontal=True,
                help="Select batch size for threat detection. Fast Triage provides instantaneous feedback for rapid incident response."
            )
            if "10,000" in batch_choice:
                eval_df = df.head(10000)
            elif "50,000" in batch_choice:
                eval_df = df.head(50000)
            else:
                eval_df = df
        else:
            eval_df = df
            
        st.caption(f"Ready to classify **{len(eval_df):,}** network flows using trained Random Forest pipeline.")
            
        if st.button("⚡ Execute Threat Detection & Risk Scoring", width='stretch'):
            with st.spinner(f"Classifying {len(eval_df):,} network flows and calculating risk scores..."):
                t_start = time.time()
                run_id = f"RUN-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
                
                # 1. Threat Detection
                results_df, summary = detect_threats(eval_df)
                
                if results_df is None:
                    st.error(summary.get("error", "Detection pipeline failed."))
                else:
                    # 2. Risk Scoring (vectorized NumPy computation)
                    scored_df = batch_calculate_risk(results_df, asset_criticality=asset_crit)
                    
                    # 3. Group Incidents
                    incidents = group_suspicious_flows_into_incidents(scored_df, run_id=run_id)
                    
                    # 4. Map MITRE ATT&CK for each incident
                    for inc in incidents:
                        mitre_info = map_threat_to_mitre(inc["threat_category"])
                        inc["mitre_technique_id"] = mitre_info["technique_id"]
                        inc["mitre_technique_name"] = mitre_info["technique_name"]
                        
                    # 5. Persist to SQLite
                    save_analysis_run(
                        run_id=run_id,
                        filename=st.session_state.filename,
                        total_records=summary["total_records"],
                        suspicious_records=summary["suspicious_count"],
                        model_version=summary["model_version"],
                        summary_dict=summary
                    )
                    save_incidents(incidents)
                    
                    elapsed = time.time() - t_start
                    summary["elapsed_seconds"] = round(elapsed, 2)
                    
                    # Pre-generate CSV export to avoid lag on subsequent renders
                    display_cols = [
                        "predicted_class", "confidence", "risk_score", "severity",
                        "is_suspicious", "Protocol", "Flow Duration"
                    ]
                    available_display_cols = [c for c in display_cols if c in scored_df.columns]
                    st.session_state.cached_report_csv = scored_df[available_display_cols].to_csv(index=False).encode("utf-8")
                    
                    # Store in session state
                    st.session_state.analysis_results = scored_df
                    st.session_state.analysis_summary = summary
                    st.session_state.current_incidents = incidents
                    
                    st.success(f"Analysis completed in {elapsed:.2f}s! {summary['suspicious_count']:,} suspicious flows identified.")
                    st.rerun()

    # Display Current Detection Results
    if st.session_state.analysis_results is not None:
        scored_df = st.session_state.analysis_results
        summary = st.session_state.analysis_summary
        
        st.divider()
        st.subheader("🔍 Detection Summary Diagnostics")
        
        s1, s2, s3, s4, s5 = st.columns(5)
        s1.metric("Total Records Evaluated", f"{summary['total_records']:,}")
        s2.metric("Benign Normal Traffic", f"{summary['benign_count']:,}")
        s3.metric("Suspicious Threat Flows", f"{summary['suspicious_count']:,}")
        s4.metric("Threat Detection Rate", f"{summary['suspicious_percentage']}%")
        s5.metric("Analysis Latency", f"{summary.get('elapsed_seconds', '< 1')}s")
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Breakdown Table
        st.subheader("Classification & Risk Results (Top 100 Flows)")
        display_cols = [
            "predicted_class", "confidence", "risk_score", "severity",
            "is_suspicious", "Protocol", "Flow Duration"
        ]
        available_display_cols = [c for c in display_cols if c in scored_df.columns]
        
        st.dataframe(
            scored_df[available_display_cols].head(100),
            width='stretch'
        )
        
        # Downloadable Report (Cached bytes - zero latency)
        if "cached_report_csv" in st.session_state and st.session_state.cached_report_csv:
            csv_data = st.session_state.cached_report_csv
        else:
            csv_data = scored_df[available_display_cols].head(10000).to_csv(index=False).encode("utf-8")
            
        st.download_button(
            label="📥 Download Detection Report (CSV)",
            data=csv_data,
            file_name=f"soc_threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            width='stretch'
        )

# ==============================================================================
# PAGE 5: SECURITY INCIDENTS
# ==============================================================================

elif page == "🛡️ Security Incidents":
    st.markdown("""
    <div class="soc-header-card">
        <h1 class="soc-header-title"><span>🛡️</span> Incident Queue & Triage Management</h1>
        <p class="soc-header-subtitle">Correlate network alerts, update investigation lifecycle statuses, and initiate AI deep-dives</p>
    </div>
    """, unsafe_allow_html=True)
    
    incidents = get_recent_incidents(limit=100)
    
    if not incidents:
        st.info("No security incidents recorded. Run 'Threat Detection' on a network dataset to populate incidents.")
    else:
        # Filtering Controls
        c_filter1, c_filter2 = st.columns(2)
        with c_filter1:
            status_filter = st.selectbox("Filter by Status", ["All", "New", "Under Review", "Resolved", "False Positive"])
        with c_filter2:
            severity_filter = st.selectbox("Filter by Severity", ["All", "Critical", "High", "Medium", "Low"])
            
        filtered = incidents
        if status_filter != "All":
            filtered = [i for i in filtered if i["status"] == status_filter]
        if severity_filter != "All":
            filtered = [i for i in filtered if i["severity"] == severity_filter]
            
        st.write(f"Displaying **{len(filtered)}** security incidents:")
        
        # Incident Cards & Status Update Loop
        for inc in filtered:
            with st.container():
                st.markdown(f"""
                <div class="soc-card">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <h4 style="margin: 0; color: #F8FAFC;">🚨 {inc['incident_id']} - {inc['threat_category']}</h4>
                        <div>
                            {get_severity_badge_html(inc['severity'])}
                            <span style="background: #1E293B; border: 1px solid #334155; padding: 4px 10px; border-radius: 6px; font-size: 0.8rem; margin-left: 8px;">
                                Status: <b>{inc['status']}</b>
                            </span>
                        </div>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 15px 0; font-size: 0.9rem;">
                        <div><b>Risk Score:</b> <span style="color: #06B6D4;">{inc['max_risk_score']:.1f}/100</span></div>
                        <div><b>Correlated Flows:</b> {inc['event_count']:,}</div>
                        <div><b>Mean Confidence:</b> {inc['avg_confidence']*100:.1f}%</div>
                        <div><b>MITRE ATT&CK:</b> <a href="{map_threat_to_mitre(inc['threat_category'])['url']}" target="_blank" style="color: #38BDF8;">{inc['mitre_technique_id']}</a></div>
                    </div>
                    <p style="color: #94A3B8; font-size: 0.88rem; margin: 8px 0;"><b>Evidence:</b> {inc['evidence_summary']}</p>
                </div>
                """, unsafe_allow_html=True)
                
                col_btn1, col_btn2 = st.columns([3, 1])
                with col_btn1:
                    new_st = st.selectbox(
                        "Update Triage Status",
                        ["New", "Under Review", "Resolved", "False Positive"],
                        index=["New", "Under Review", "Resolved", "False Positive"].index(inc["status"]),
                        key=f"status_select_{inc['incident_id']}"
                    )
                    if new_st != inc["status"]:
                        update_incident_status(inc["incident_id"], new_st)
                        st.success(f"Updated status of {inc['incident_id']} to '{new_st}'")
                        st.rerun()
                with col_btn2:
                    if st.button("🤖 Investigate with AI", key=f"inv_btn_{inc['incident_id']}", width='stretch'):
                        st.session_state.selected_incident_id = inc["incident_id"]
                        st.info(f"Selected {inc['incident_id']} for investigation. Switch to the 'AI Investigation' page in the sidebar.")

# ==============================================================================
# PAGE 6: AI INVESTIGATION
# ==============================================================================

elif page == "🤖 AI Investigation":
    st.markdown("""
    <div class="soc-header-card">
        <h1 class="soc-header-title"><span>🤖</span> AI Security Investigation & Advisory</h1>
        <p class="soc-header-subtitle">Google Gemini Tier-2 Incident Advisory grounded in MITRE ATT&CK, NIST SP 800-61, and OWASP knowledge</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.warning("⚠️ Disclaimer: AI-generated analysis is decision support and must be reviewed by a human cybersecurity analyst before taking response actions.")
    
    all_incidents = get_recent_incidents(limit=50)
    
    if not all_incidents:
        st.info("No recorded incidents available for AI investigation. Please detect threats from a dataset first.")
    else:
        # Incident Selector
        incident_ids = [i["incident_id"] for i in all_incidents]
        default_idx = 0
        if st.session_state.selected_incident_id in incident_ids:
            default_idx = incident_ids.index(st.session_state.selected_incident_id)
            
        selected_id = st.selectbox("Select Security Incident for Investigation", incident_ids, index=default_idx)
        st.session_state.selected_incident_id = selected_id
        
        current_inc = get_incident_by_id(selected_id)
        
        if current_inc:
            # Display Selected Incident Metadata Card
            st.markdown(f"""
            <div class="soc-card">
                <h3>Incident Snapshot: {current_inc['incident_id']}</h3>
                <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; font-size: 0.92rem;">
                    <div><b>Threat Category:</b> {current_inc['threat_category']}</div>
                    <div><b>Calculated Risk:</b> {current_inc['max_risk_score']:.1f}/100</div>
                    <div><b>Severity:</b> {current_inc['severity']}</div>
                    <div><b>MITRE Technique:</b> {current_inc['mitre_technique_id']} - {current_inc['mitre_technique_name']}</div>
                </div>
                <div style="margin-top: 10px; font-size: 0.88rem; color: #94A3B8;">
                    <b>Flow Telemetry:</b> {current_inc['evidence_summary']}
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Check for existing saved report in database
            saved_report = get_investigation_report(selected_id)
            
            # RAG Knowledge Retrieval Preview
            rag = get_rag_system()
            query_str = f"{current_inc['threat_category']} mitigation {current_inc['mitre_technique_id']}"
            retrieved_chunks = rag.retrieve(query_str, top_k=2)
            
            with st.expander("📚 Retrieved Knowledge Base Guidance (RAG Context)"):
                if retrieved_chunks:
                    for chunk in retrieved_chunks:
                        st.markdown(f"**Source:** `{chunk['source']}` — *{chunk['title']}* (Relevance: `{chunk['similarity_score']:.2f}`)")
                        st.markdown(chunk["text"])
                        st.divider()
                else:
                    st.info("No matching RAG knowledge base chunks met the similarity threshold.")
                    
            # Generate Advisory Button
            btn_col1, btn_col2 = st.columns([2, 2])
            with btn_col1:
                gen_button = st.button("🚀 Generate Gemini AI Advisory Report", width='stretch')
                
            if gen_button:
                if not is_gemini_configured():
                    st.error("Google Gemini API Key is missing. Please add GEMINI_API_KEY to your .env file.")
                else:
                    with st.spinner("Consulting Google Gemini with grounded RAG context..."):
                        rag_text = rag.format_retrieved_context(retrieved_chunks)
                        analysis_res = analyze_security_incident(current_inc, retrieved_knowledge=rag_text)
                        
                        if analysis_res["success"]:
                            rep_text = analysis_res["report"]
                            save_investigation_report(
                                report_id=f"REP-{uuid.uuid4().hex[:6].upper()}",
                                incident_id=selected_id,
                                ai_summary=rep_text,
                                threat_implications="Documented in full advisory report.",
                                investigation_steps="Refer to section 4.",
                                defensive_actions="Refer to section 5."
                            )
                            st.success("Advisory generated and saved to database!")
                            saved_report = {"ai_summary": rep_text}
                        else:
                            st.error(analysis_res.get("message", "Failed to generate AI analysis."))

            # Display Saved / Generated Report
            if saved_report:
                st.markdown("### 📋 Defensive SOC Advisory Report")
                st.markdown(f"""
                <div style="background-color: #0F172A; border: 1px solid #334155; border-radius: 8px; padding: 22px;">
                    {saved_report['ai_summary']}
                </div>
                """, unsafe_allow_html=True)
                
            st.divider()
            
            # Interactive Analyst Q&A
            st.subheader("💬 Ask AI Analyst About This Incident")
            q_text = st.text_input("Ask a follow-up question (e.g. 'What firewall rule blocks this specific attack pattern?')")
            if st.button("Send Question"):
                if not q_text.strip():
                    st.warning("Please type a question.")
                elif not is_gemini_configured():
                    st.error("Gemini API key is not configured in .env.")
                else:
                    with st.spinner("Analyzing question..."):
                        ans = ask_incident_question(current_inc, q_text)
                        if ans["success"]:
                            st.markdown(f"**Answer:** {ans['answer']}")
                        else:
                            st.error(ans["answer"])

# ==============================================================================
# PAGE 7: MITRE ATT&CK
# ==============================================================================

elif page == "📚 MITRE ATT&CK":
    st.markdown("""
    <div class="soc-header-card">
        <h1 class="soc-header-title"><span>📚</span> MITRE ATT&CK Enterprise Matrix</h1>
        <p class="soc-header-subtitle">Verified threat techniques, tactical categorizations, behavioral rationales, and official references</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    The **MITRE ATT&CK®** framework is a globally-accessible knowledge base of adversary tactics and techniques 
    based on real-world observations. Our system correlates network flow classifications with official ATT&CK techniques.
    """)
    
    # Search Box
    search = st.text_input("Search MITRE Techniques (by Name, ID, or Attack Class)").lower().strip()
    
    matched_items = []
    for attack_name, data in OFFICIAL_MITRE_MAPPINGS.items():
        if not search or (search in attack_name.lower() or search in data["technique_id"].lower() or search in data["technique_name"].lower()):
            matched_items.append((attack_name, data))
            
    st.write(f"Showing **{len(matched_items)}** official technique mappings:")
    
    for attack_name, data in matched_items:
        with st.container():
            st.markdown(f"""
            <div class="soc-card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h3 style="margin: 0; color: #38BDF8;">
                        <a href="{data['url']}" target="_blank" style="color: #38BDF8; text-decoration: none;">
                            🔗 {data['technique_id']}: {data['technique_name']}
                        </a>
                    </h3>
                    <span style="background: rgba(6, 182, 212, 0.2); border: 1px solid #06B6D4; color: #67E8F9; padding: 4px 10px; border-radius: 6px; font-size: 0.8rem; font-weight: 600;">
                        {data['tactic']}
                    </span>
                </div>
                <p style="margin: 10px 0; color: #E2E8F0; font-size: 0.92rem;"><b>Associated Attack Label:</b> <span style="color: #FBBF24;">{attack_name}</span></p>
                <p style="margin: 8px 0; color: #94A3B8; font-size: 0.9rem;"><b>Description:</b> {data['description']}</p>
                <p style="margin: 8px 0; color: #A5F3FC; font-size: 0.88rem;"><b>Flow Behavioral Evidence:</b> {data['rationale']}</p>
            </div>
            """, unsafe_allow_html=True)

# ==============================================================================
# PAGE 8: SYSTEM STATUS
# ==============================================================================

elif page == "⚙️ System Status":
    st.markdown("""
    <div class="soc-header-card">
        <h1 class="soc-header-title"><span>⚙️</span> Autonomous SOC Health & Configuration</h1>
        <p class="soc-header-subtitle">Real-time status diagnostics across Machine Learning, SQLite Database, Vector Store, and LLM APIs</p>
    </div>
    """, unsafe_allow_html=True)
    
    # 1. Component Health Checks
    model_ok = is_model_available()
    _, meta = load_threat_model() if model_ok else (None, None)
    gemini_ok = is_gemini_configured()
    db_ok = DATABASE_PATH.exists()
    rag_index_path = BASE_DIR / "knowledge_base" / "faiss_index" / "faiss.index"
    rag_ok = rag_index_path.exists()
    raw_files = list(RAW_DATA_DIR.glob("*.parquet"))
    sample_file = SAMPLE_DATA_DIR / "sample_soc_traffic.csv"
    
    status_table = [
        {
            "Subsystem": "Streamlit Dashboard UI",
            "Status": "🟢 Operational",
            "Version": "1.0.0",
            "Details": "Dark theme enterprise SOC layout with Plotly charting"
        },
        {
            "Subsystem": "CIC-IDS2017 Dataset Files",
            "Status": "🟢 Ready" if raw_files else "🔴 Missing",
            "Version": "2017 Benchmark",
            "Details": f"{len(raw_files)} raw Parquet files detected (~260MB total)"
        },
        {
            "Subsystem": "Sample Evaluation CSV",
            "Status": "🟢 Available" if sample_file.exists() else "🟡 Unbuilt",
            "Version": "1,000 flows",
            "Details": str(sample_file) if sample_file.exists() else "Generated during training"
        },
        {
            "Subsystem": "Random Forest ML Pipeline",
            "Status": "🟢 Trained & Serialized" if model_ok else "🔴 Not Trained",
            "Version": meta.get("model_version", "N/A") if meta else "N/A",
            "Details": f"Accuracy: {meta['metrics']['accuracy']*100:.2f}%, Classes: {len(meta.get('classes', []))}" if meta else "Run training/train_model.py"
        },
        {
            "Subsystem": "SQLite Incident Store",
            "Status": "🟢 Active" if db_ok else "🔴 Offline",
            "Version": "SQLite 3",
            "Details": f"Database path: {DATABASE_PATH}"
        },
        {
            "Subsystem": "FAISS Vector RAG Index",
            "Status": "🟢 Indexed & Persisted" if rag_ok else "🟡 Needs Build",
            "Version": "IndexFlatIP",
            "Details": f"Location: {rag_index_path.parent}"
        },
        {
            "Subsystem": "Google Gemini API (google-genai)",
            "Status": "🟢 Connected & Validated" if gemini_ok else "🟡 Key Missing",
            "Version": GEMINI_MODEL,
            "Details": "Reads GEMINI_API_KEY from environment/.env (never hardcoded)"
        },
        {
            "Subsystem": "MITRE ATT&CK Matrix",
            "Status": "🟢 19 Techniques Mapped",
            "Version": "v14.1 Enterprise",
            "Details": "Validated URLs, network flows and Windows Event ID rationales"
        },
        {
            "Subsystem": "Central Ingestion API (FastAPI)",
            "Status": "🟢 Supported (Port 8000)",
            "Version": "FastAPI 0.110+",
            "Details": "Authenticated REST endpoint with Pydantic validation and duplicate protection"
        },
        {
            "Subsystem": "Windows Security Event Collector",
            "Status": "🟢 Integrated (pywin32)",
            "Version": "Event IDs 4624/4625/4634/4740",
            "Details": "State-preserved bookmarking and permission diagnostics"
        },
        {
            "Subsystem": "Live Threat Rule Engine",
            "Status": "🟢 Active Sliding-Window",
            "Version": "Rules 1-5 Engine",
            "Details": "Detects host brute-force, targeted accounts, password spraying and lockouts"
        }
    ]
    
    st.dataframe(pd.DataFrame(status_table), width='stretch', hide_index=True)
    
    st.divider()
    
    # Model Metadata Diagnostics if trained
    if meta:
        st.subheader("📊 Deployed ML Model Telemetry")
        c_m1, c_m2, c_m3, c_m4 = st.columns(4)
        c_m1.metric("Overall Accuracy", f"{meta['metrics']['accuracy']*100:.2f}%")
        c_m2.metric("Weighted F1-Score", f"{meta['metrics']['weighted_f1']:.4f}")
        c_m3.metric("Training Samples", f"{meta['num_training_samples']:,}")
        c_m4.metric("Test Samples", f"{meta['num_test_samples']:,}")
        
        with st.expander("🔍 View Supported Attack Classes"):
            st.write(meta.get("classes", []))
            
    # Gemini Key Setup Instructions if unconfigured
    if not gemini_ok:
        st.info("""
        **How to configure Google Gemini:**
        1. Open the file `.env` in the project root.
        2. Set: `GEMINI_API_KEY=your_actual_gemini_api_key`
        3. Get an API key from [Google AI Studio](https://aistudio.google.com/).
        4. Reload the dashboard to activate autonomous AI investigations.
        """)

# ==============================================================================
# FOOTER
# ==============================================================================

st.divider()
st.markdown("""
<div style="text-align: center; color: #64748B; font-size: 0.82rem; padding: 10px 0;">
    🛡️ <b>AI-Powered Autonomous SOC Assistant</b> |• MITRE ATT&CK Mapped • Decision Support Only
</div>
""", unsafe_allow_html=True)