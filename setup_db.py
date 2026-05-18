from pymongo import MongoClient
from passlib.context import CryptContext

# 1. Cấu hình thuật toán băm mật khẩu (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

# 2. Kết nối tới MongoDB (Đảm bảo Database đang chạy)
print("Đang kết nối tới MongoDB...")
client = MongoClient("mongodb://localhost:27017/")
db = client["ai_ids_database"]
users_col = db["users"] # Tạo collection 'users'

# 3. Định nghĩa danh sách tài khoản cần tạo
# Cấu trúc: username, password (chưa mã hóa), role
initial_users = [
    {
        "username": "admin",
        "password_clear": "123456", 
        "role": "admin"
    },
    {
        "username": "guest",
        "password_clear": "123456",
        "role": "monitor"
    }
]

# 4. Mã hóa và đẩy vào Database
print("Bắt đầu khởi tạo tài khoản...")
for user in initial_users:
    # Kiểm tra xem user đã tồn tại chưa để tránh tạo trùng lặp
    existing_user = users_col.find_one({"username": user["username"]})
    if existing_user:
        print(f"⚠️ Tài khoản '{user['username']}' đã tồn tại, bỏ qua.")
        continue
    
    # Băm mật khẩu
    hashed_password = get_password_hash(user["password_clear"])
    
    # Tạo document để lưu vào DB (KHÔNG LƯU password_clear)
    user_doc = {
        "username": user["username"],
        "hashed_password": hashed_password,
        "role": user["role"]
    }
    
    users_col.insert_one(user_doc)
    print(f"✅ Đã tạo thành công tài khoản '{user['username']}' với mật khẩu đã mã hóa!")

print("Hoàn tất thiết lập Database!")