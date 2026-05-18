import streamlit as st
import pandas as pd
import requests

# ===== 1. Cấu hình trang & CSS =====
st.set_page_config(page_title="AI Network Detection", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    [data-testid="stDataFrame"] td, [data-testid="stDataFrame"] th {
        font-size: 18px !important;
    }
    .table-title {
        font-size: 30px !important;
        font-weight: bold;
        margin-top: 20px;
    }
    .stButton button {
        font-size: 20px !important;
        height: 3em !important;
        width: 100% !important;
    }
    </style>
    """, unsafe_allow_html=True)

# ===== 2. Khai báo các hàm xử lý API =====
API_URL = "http://localhost:8000"

def trigger_attack(attack_type):
    try:
        requests.post(f"{API_URL}/attack", json={"type": attack_type}, timeout=2)
        st.toast(f"🚀 {attack_type.upper()} started!")
    except:
        st.error("❌ Không kết nối được với Backend")

def stop_attack():
    try:
        requests.post(f"{API_URL}/stop", timeout=2)
        st.toast("🛑 Đã dừng mọi cuộc tấn công")
    except:
        st.error("❌ Không kết nối được với Backend")

def explain_ai(status, latency, noport, ip_in, icmp_in):
    reasons = []
    l, n, ip, ic = float(latency), float(noport), float(ip_in), float(icmp_in)
    
    if status == "UDP" and n > 0: reasons.append(f"Traffic UDP in closed ports high ({int(n)})")
    elif status == "ICMP" and ic > 0: reasons.append(f"ICMP Echo packets increase rapidly ({int(ic)})")
    elif status == "SYN" and ip > 1000: reasons.append(f"SYN packets flooding ({int(ip)})")
    elif status == "SCAN" and n > 0: reasons.append(f"Many ports being scanned ({int(n)})")
    
    if l > 0.2: reasons.append(f"System latency increased ({l:.3f}s)")
    return reasons

# ===== 3. Giao diện Header & Panels =====
st.title("Real-time Intrusion Detection Dashboard")

status_box = st.empty()
metric_box = st.empty()
explain_box = st.empty()

st.write("---")
st.subheader("Attack Control Panel")
col_a, col_b, col_c, col_d, col_e = st.columns(5)

with col_a: st.button("🌊 ICMP Flood", on_click=trigger_attack, args=("icmp",))
with col_b: st.button("🔍 Port Scan", on_click=trigger_attack, args=("scan",))
with col_c: st.button("📦 UDP Flood", on_click=trigger_attack, args=("udp",))
with col_d: st.button("⚡ SYN Flood", on_click=trigger_attack, args=("syn",))
with col_e: st.button("🛑 STOP ALL", on_click=stop_attack)

table_placeholder = st.empty()

if "last_status" not in st.session_state:
    st.session_state.last_status = None

# ===== 4. Vòng lặp cập nhật UI từ API MongoDB =====
@st.fragment(run_every="7s")
def update_ui():
    # --- Đọc trạng thái hiện tại (LIVE) ---
    try:
        res_live = requests.get(f"{API_URL}/api/live_status", timeout=2)
        if res_live.status_code == 200:
            data = res_live.json()
            
            if data.get("status") == "WAITING":
                status_box.info("⏳ Waiting for data from Detector...")
            else:
                status = data["status"]
                conf = data["confidence"]
                lat = data["latency"]
                noport = data["udpNoPorts"]
                ip_in = data["ipInReceives"]
                icmp_in = data["icmpInEchos"]
                t = data["timestamp"]

                # Cập nhật Status Box
                if status == "NORMAL":
                    status_box.success(f"### ✅ {status} ({conf}%)\nTime: {t}")
                else:
                    status_box.error(f"### 🚨 {status} ({conf}%)\nTime: {t}")
                    if st.session_state.last_status != status:
                        st.toast(f"Detected {status}!")

                # Cập nhật Metrics
                with metric_box.container():
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Latency", f"{float(lat):.4f}s", delta="⚠️" if float(lat) > 0.2 else None)
                    c2.metric("NoPort Errors", int(float(noport)), delta="⚠️" if float(noport) > 0 else None)
                    c3.metric("IP In", int(float(ip_in)), delta="⚠️" if float(ip_in) > 1000 else None)
                    c4.metric("ICMP In", int(float(icmp_in)), delta="⚠️" if float(icmp_in) > 0 else None)

                # Giải thích AI
                if status != "NORMAL":
                    reasons = explain_ai(status, lat, noport, ip_in, icmp_in)
                    with explain_box.container():
                        st.markdown("### Explain AI 🧠")
                        for r in reasons: st.markdown(f"- {r}")
                else:
                    explain_box.empty()
                    
                st.session_state.last_status = status
    except Exception as e:
        status_box.warning("🔌 Đang mất kết nối với Backend. Vui lòng bật FastAPI...")

    # --- Đọc hiển thị Lịch sử (HISTORY) ---
    try:
        res_history = requests.get(f"{API_URL}/api/history?limit=10", timeout=2)
        if res_history.status_code == 200:
            history_data = res_history.json()
            
            if history_data:
                # Đưa data JSON vào Pandas DataFrame
                df = pd.DataFrame(history_data)
                
                # Đổi tên cột cho đẹp
                df = df.rename(columns={
                    "timestamp": "Time", "status": "Status", "confidence": "Confidence (%)",
                    "latency": "Latency", "udpNoPorts": "UDP in closed ports",
                    "ipInReceives": "IP", "icmpInEchos": "ICMP"
                })

                # Highlight cảnh báo đỏ (giống code cũ)
                def highlight(row):
                    styles = [""] * len(row)
                    try:
                        if row["Status"] != "NORMAL":
                            if float(row["UDP in closed ports"]) > 0: styles[df.columns.get_loc("UDP in closed ports")] = "color: red; font-weight: bold"
                            if float(row["IP"]) > 1000: styles[df.columns.get_loc("IP")] = "color: red; font-weight: bold"
                            if float(row["ICMP"]) > 0: styles[df.columns.get_loc("ICMP")] = "color: red; font-weight: bold"
                            if float(row["Latency"]) > 0.2: styles[df.columns.get_loc("Latency")] = "color: red; font-weight: bold"
                    except:
                        pass
                    return styles

                styled_df = df.style.apply(highlight, axis=1)

                with table_placeholder.container():
                    st.write("---")
                    st.markdown('<p class="table-title">RECENT ACTIVITY LOG</p>', unsafe_allow_html=True)
                    st.write(styled_df)
            else:
                table_placeholder.info("Chưa có lịch sử tấn công nào.")
    except:
        pass

# Chạy UI
update_ui()