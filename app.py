from flask import Flask, request, jsonify, session, render_template, redirect
import os
import json
import logging
import sqlite3
from datetime import datetime, timedelta
import hashlib
from auth import get_user_info_with_password

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ================= 通用配置 =================
CONFIG_DIR = "/app/cache/config"
DEVICE_ID_FILE = os.path.join(CONFIG_DIR, "device_id")
CONFIG_FILE = os.path.join(CONFIG_DIR, "115_config.json")

# 下载缓存配置
CACHE_DB = "/app/cache/download_cache.db"
CACHE_TTL = 20 * 60 * 60  # 20小时

# ================= 初始化配置 =================
def init_system_files():
    """初始化系统必要文件"""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    
    # 初始化设备ID
    if not os.path.exists(DEVICE_ID_FILE):
        with open(DEVICE_ID_FILE, "w") as f:
            f.write(os.urandom(16).hex())
        os.chmod(DEVICE_ID_FILE, 0o666)
    
    # 初始化115配置文件
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump({
                "main": {},
                "subs": [],
                "schedule_time": "08:00"
            }, f, indent=2)
        os.chmod(CONFIG_FILE, 0o666)

    # 初始化下载缓存数据库
    with sqlite3.connect(CACHE_DB) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS download_cache (
                key TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                expire_time TIMESTAMP NOT NULL
            )
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_expire ON download_cache (expire_time)')
        conn.commit()

# ================= 路由定义 =================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/init_config')
def init_config():
    init_system_files()
    return jsonify({"success": True})

# --------------- 用户认证 ---------------
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        passport = data.get('passport')
        password = data.get('password')
        
        user_info = get_user_info_with_password(passport, password)
        if user_info.get("code") != 0:
            return jsonify({"success": False, "message": user_info.get("message", "登录失败")})

        session['logged_in'] = True
        session['user_info'] = user_info['data']
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": "服务器错误"})

@app.route('/user_info')
def get_user_info():
    return jsonify({
        "logged_in": session.get('logged_in', False),
        "user_info": session.get('user_info', {})
    })

@app.route('/logout')
def logout():
    session.clear()
    return jsonify({"success": True})

# --------------- 115配置管理 ---------------
@app.route('/115_config', methods=['GET', 'POST'])
def handle_115_config():
    try:
        if request.method == 'POST':
            # 写入配置
            with open(CONFIG_FILE, 'w') as f:
                json.dump(request.json, f, indent=2)
            return jsonify({"success": True})
        else:
            # 读取配置
            with open(CONFIG_FILE, 'r') as f:
                return jsonify(json.load(f))
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

# --------------- 下载缓存管理 ---------------
def generate_cache_key(file_name: str, size: int, etag: str) -> str:
    raw_key = f"{file_name}|{size}|{etag}"
    return hashlib.sha256(raw_key.encode()).hexdigest()

@app.route('/<path:uri>', methods=['GET', 'HEAD'])
def handle_request(uri: str):
    try:
        if uri.count("|") < 2:
            raise ValueError("URI格式错误")
        
        file_name, size, etag_part = uri.rsplit("|", 2)
        etag = etag_part.split("?")[0]
        size = int(size)
        cache_key = generate_cache_key(file_name, size, etag)

        with sqlite3.connect(CACHE_DB) as conn:
            cursor = conn.execute(
                '''
                SELECT url 
                FROM download_cache 
                WHERE 
                    key = ? 
                    AND expire_time > datetime('now')
                ''',
                (cache_key,)
            )
            if row := cursor.fetchone():
                return redirect(row[0], code=302)

        # 模拟下载逻辑（实际应调用客户端API）
        download_url = f"http://example.com/download/{file_name}"
        expire_time = (datetime.now() + timedelta(seconds=CACHE_TTL)).strftime("%Y-%m-%d %H:%M:%S")
        with sqlite3.connect(CACHE_DB) as conn:
            conn.execute(
                '''
                INSERT OR REPLACE INTO download_cache 
                (key, url, expire_time) 
                VALUES (?, ?, ?)
                ''',
                (cache_key, download_url, expire_time)
            )
            conn.commit()
        
        return redirect(download_url, code=302)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# --------------- 任务执行 ---------------
@app.route('/115_run_now', methods=['POST'])
def run_115_now():
    try:
        # 这里调用实际的任务执行逻辑
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

if __name__ == "__main__":
    init_system_files()
    app.run(host="0.0.0.0", port=8124)
