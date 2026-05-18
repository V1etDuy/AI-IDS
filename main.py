from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from contextlib import asynccontextmanager
from pymongo import MongoClient
import threading
import paramiko
import time
import requests
import json
import joblib
import pandas as pd
from datetime import datetime
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from datetime import datetime



# ================= 1. CẤU HÌNH HỆ THỐNG =================
# Cấu hình GNS3 (Từ attack_docker.py)
GNS3_VM_IP = "192.168.147.128"
SSH_USER = "gns3"
SSH_PASS = "gns3"
CONTAINER_NAME = "GNS3.Attacker.7bd65ce8-264b-4778-b7ad-dd1ba45fdfcb"
TARGET_IP = "192.168.10.1"

# Cấu hình Zabbix & Model (Từ detector.py)
ZABBIX_URL = "http://192.168.30.10/api_jsonrpc.php"
TOKEN = "e34ed1fed6a74916482fde40bc96dcfe"
HOST_NAME = "Router_R1"
MODEL_PATH = "ids_xgboost_model.pkl"  
ENCODER_PATH = "label_encoder.pkl"    
HEADERS = {
    "Content-Type": "application/json-rpc",
    "Authorization": f"Bearer {TOKEN}"
}

# ================= 2. KẾT NỐI MONGODB =================
client = MongoClient("mongodb://localhost:27017/")
db = client["ai_ids_database"]
status_col = db["live_status"]    # Lưu trạng thái mới nhất
history_col = db["history_logs"]  # Lưu lịch sử tấn công

# ================= 3. KHỞI TẠO AI MODEL =================
try:
    model = joblib.load(MODEL_PATH)
    le = joblib.load(ENCODER_PATH)
    features_list = list(model.feature_names_in_)
    print("✅ Đã tải Model XGBoost & Label Encoder!")
except Exception as e:
    print(f"❌ Lỗi tải model: {e}")

# ================= 4. LOGIC ĐIỀU KHIỂN TẤN CÔNG =================
ATTACK_COMMANDS = {
    "icmp": f"hping3 -1 --flood --rand-source {TARGET_IP}",
    "udp": f"hping3 -2 --flood -p 80 {TARGET_IP}",
    "syn": f"hping3 -S --flood --rand-source -p 80 {TARGET_IP}",
    "scan": f"while true; do nmap -sS -p 1-1024 --min-rate 1000 {TARGET_IP}; nmap -sU -p 1-1024 --min-rate 500 {TARGET_IP}; done",
}
STOP_COMMAND = "pkill -9 -f hping3; pkill -9 -f nmap; pkill -9 -f nping;"

def run_remote_cmd(cmd, detach=True):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(GNS3_VM_IP, username=SSH_USER, password=SSH_PASS)
        safe_cmd = cmd.replace('"', '\\"')
        
        if detach:
            full_cmd = f'sudo docker exec -d {CONTAINER_NAME} sh -c "{safe_cmd}"'
        else:
            full_cmd = f'sudo docker exec {CONTAINER_NAME} sh -c "{safe_cmd}"'
            
        ssh.exec_command(full_cmd)
        time.sleep(1)
        ssh.close()
        return True
    except Exception as e:
        print(f"❌ Lỗi SSH: {e}")
        return False

# ================= 5. LOGIC ZABBIX & NHẬN DIỆN (CHẠY NGẦM) =================
prev_raw_data = {}
prev_last_clock = 0

def zabbix_api(method, params):
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    try:
        res = requests.post(ZABBIX_URL, data=json.dumps(payload), headers=HEADERS, timeout=5)
        return res.json()
    except:
        return None

def get_host_id(host_name):
    res = zabbix_api("host.get", {"filter": {"host": [host_name]}, "output": ["hostid"]})
    return res["result"][0]["hostid"] if res and res.get("result") else None

def get_all_items(host_id):
    res = zabbix_api("item.get", {"hostids": host_id, "output": ["itemid", "key_", "lastvalue", "lastclock"], "filter": {"status": 0}})
    return res.get("result", []) if res else []

def extract_and_compute_delta(items):
    global prev_raw_data, prev_last_clock
    current_max_clock = max([int(i.get('lastclock', 0)) for i in items])
    if current_max_clock <= prev_last_clock:
        return None
    prev_last_clock = current_max_clock

    KEY_MAP = {
        "icmppingsec": "icmppingsec", "net.if.in[ifHCInOctets.1]": "ifHCInOctets.1",
        "net.if.out[ifHCOutOctets.1]": "ifHCOutOctets.1", "udpInDatagrams": "udpInDatagrams",
        "icmpInEchos": "icmpInEchos", "udpNoPorts": "udpNoPorts", "ipInReceives": "ipInReceives"
    }

    current_raw = {}
    for item in items:
        key = item["key_"]
        if key in KEY_MAP:
            try:
                current_raw[KEY_MAP[key]] = float(item["lastvalue"])
            except:
                current_raw[KEY_MAP[key]] = 0.0

    if not prev_raw_data:
        prev_raw_data = current_raw
        return None

    delta_data = {}
    for col, val in current_raw.items():
        if col in ["ifHCInOctets.1", "ifHCOutOctets.1", "udpInDatagrams", "icmpInEchos", "udpNoPorts", "ipInReceives"]:
            delta_data[col] = max(0.0, val - prev_raw_data.get(col, val))
        else:
            delta_data[col] = val

    delta_data["diff_if1"] = delta_data.get("ifHCInOctets.1", 0) - delta_data.get("ifHCOutOctets.1", 0)
    prev_raw_data = current_raw

    df = pd.DataFrame([delta_data])
    for col in features_list:
        if col not in df.columns: df[col] = 0.0
    return df[features_list], delta_data

def detection_loop():
    print("🛡️ AI IDS đang chạy ngầm...")
    host_id = get_host_id(HOST_NAME)
    attack_streak = 0
    last_attack = "NORMAL"

    while True:
        items = get_all_items(host_id)
        result = extract_and_compute_delta(items)
        if result is None:
            time.sleep(1)
            continue
            
        df_now, raw_metrics = result
        
        # Dự đoán
        pred_numeric = model.predict(df_now)[0]
        probs = model.predict_proba(df_now)[0]
        confidence = max(probs) * 100
        pred = le.inverse_transform([pred_numeric])[0].upper()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Đóng gói dữ liệu chuẩn bị lưu Database
        doc = {
            "timestamp": timestamp,
            "status": str(pred),
            "confidence": float(round(confidence, 1)),
            "latency": float(raw_metrics.get('icmppingsec', 0)),
            "udpNoPorts": float(raw_metrics.get('udpNoPorts', 0)),
            "ipInReceives": float(raw_metrics.get('ipInReceives', 0)),
            "icmpInEchos": float(raw_metrics.get('icmpInEchos', 0)),
            "ethIn": float(raw_metrics.get('ifHCInOctets.1', 0)),
            "ethOut": float(raw_metrics.get('ifHCOutOctets.1', 0)),
            "udpIn": float(raw_metrics.get('udpInDatagrams', 0))
        }

        # 1. Cập nhật trạng thái LIVE (Chỉ giữ 1 bản ghi duy nhất)
        status_col.update_one({"_id": "current_status"}, {"$set": doc}, upsert=True)

        # 2. Xử lý lưu Lịch sử (Chỉ lưu khi có biến hoặc streak)
        if pred != "NORMAL":
            if pred == last_attack:
                attack_streak += 1
            else:
                attack_streak = 1
                last_attack = pred
        else:
            attack_streak = 0
            last_attack = "NORMAL"

        if pred == "NORMAL" or attack_streak >= 3:
             # Nếu trạng thái thay đổi so với bản ghi cuối trong lịch sử thì mới lưu mới
             last_log = history_col.find_one(sort=[("_id", -1)])
             if not last_log or last_log.get("status") != pred:
                 history_col.insert_one(doc)
                 print(f"[{timestamp}] Đã lưu log vào DB: {pred}")

        time.sleep(7)

# ================= 6. FASTAPI ENDPOINTS =================
# Quản lý luồng chạy ngầm khi bật server
@asynccontextmanager
async def lifespan(app: FastAPI):
    thread = threading.Thread(target=detection_loop, daemon=True)
    thread.start()
    yield

app = FastAPI(title="AI IDS Backend", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
class AttackRequest(BaseModel):
    type: str

# Cấu hình mã hóa mật khẩu
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Schema cho request tạo User
class UserCreate(BaseModel):
    username: str
    password: str
    role: str

class LoginRequest(BaseModel):
    username: str
    password: str

# API Lấy danh sách User (Chỉ trả về các thông tin an toàn, KHÔNG trả về password)
@app.get("/api/users")
def get_all_users():
    users = list(db["users"].find({}, {"_id": 0, "hashed_password": 0}))
    
    # Sắp xếp: role "admin" đứng trước (True/False logic trong Python), sau đó xếp theo tên
    users.sort(key=lambda x: (x.get("role") != "admin", x.get("username")))
    
    return users

# API Thêm User mới
@app.post("/api/users")
def create_user(user: UserCreate):
    # Kiểm tra xem user đã tồn tại chưa
    if db["users"].find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username đã tồn tại!")
    
    # Tạo user mới với mật khẩu đã mã hóa
    new_user = {
        "username": user.username,
        "hashed_password": pwd_context.hash(user.password),
        "role": user.role,
        "last_login": "Chưa đăng nhập" # Sẽ cập nhật khi user gọi hàm login
    }
    db["users"].insert_one(new_user)
    return {"message": f"Đã tạo thành công tài khoản {user.username}"}

# API Xóa User
@app.delete("/api/users/{username}")
def delete_user(username: str):
    # Bảo vệ: Không cho phép xóa tài khoản Admin gốc
    if username == "admin":
        raise HTTPException(status_code=400, detail="Không thể xóa tài khoản Admin hệ thống!")
        
    result = db["users"].delete_one({"username": username})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản này!")
        
    return {"message": f"Đã xóa thành công tài khoản {username}"}

@app.post("/attack")
def trigger_attack(req: AttackRequest):
    if req.type not in ATTACK_COMMANDS:
        raise HTTPException(status_code=400, detail="Invalid attack type")
    run_remote_cmd(STOP_COMMAND, detach=False)
    ok = run_remote_cmd(ATTACK_COMMANDS[req.type], detach=True)
    if ok:
        return {"status": "started", "attack": req.type}
    raise HTTPException(status_code=500, detail="Failed to start attack")

@app.post("/stop")
def stop_attacks():
    ok = run_remote_cmd(STOP_COMMAND, detach=False)
    if ok:
        return {"status": "stopped"}
    raise HTTPException(status_code=500, detail="Failed to stop attacks")

@app.get("/api/live_status")
def get_live_status():
    data = status_col.find_one({"_id": "current_status"}, {"_id": 0})
    return data if data else {"status": "WAITING"}

@app.get("/api/history")
def get_history(limit: int = 10):
    # Lấy n bản ghi mới nhất
    logs = list(history_col.find({}, {"_id": 0}).sort("_id", -1).limit(limit))
    return logs

@app.post("/login")
def login(req: LoginRequest):
    # 1. Tìm user trong Database
    user = db["users"].find_one({"username": req.username})
    
    # 2. Kiểm tra user có tồn tại không và mật khẩu có khớp không
    if not user or not pwd_context.verify(req.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Sai tài khoản hoặc mật khẩu!")
    
    # 3. Cập nhật thời gian đăng nhập cuối
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db["users"].update_one(
        {"username": req.username},
        {"$set": {"last_login": current_time}}
    )
    
    # 4. Sinh Token và trả về (Tạm thời dùng token đơn giản, nếu thích sau này nâng cấp JWT thật)
    return {
        "access_token": f"mock_jwt_token_{user['role']}",
        "role": user["role"]
    }