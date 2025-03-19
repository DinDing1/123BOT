from flask import Flask, request, jsonify, render_template, session
from collections import deque
import os
import logging
import sqlite3
from datetime import datetime, timedelta
import hashlib
from apscheduler.schedulers.background import BackgroundScheduler
import json
from auth import get_user_info_with_password
from werkzeug.serving import WSGIRequestHandler
import subprocess  # 导入 subprocess 模块

# ------------------- 基础配置 -------------------
# 日志存储（使用 deque 限制最大日志条数）
log_store = deque(maxlen=1000)  # 最多存储 1000 条日志

app = Flask(__name__)
app.secret_key = os.urandom(24)  # 设置 session 密钥

# ------------------- 日志配置 -------------------
# 禁用 Flask 默认日志
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# 禁用第三方库的冗余日志
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").disabled = True
logging.getLogger("uvicorn.error").disabled = True
logging.getLogger("fastapi").setLevel(logging.WARNING)
logging.getLogger("apscheduler").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("p123").setLevel(logging.WARNING)

# ------------------- 数据库配置 -------------------
CACHE_DB = "/app/cache/download_cache.db"
CACHE_TTL = 20 * 60 * 60  # 20小时

def init_db():
    """初始化数据库结构"""
    try:
        with sqlite3.connect(CACHE_DB) as conn:
            # 下载缓存表
            conn.execute('''
                CREATE TABLE IF NOT EXISTS download_cache (
                    key TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    expire_time TIMESTAMP NOT NULL
                )''')
            
            # 115配置表
            conn.execute('''
                CREATE TABLE IF NOT EXISTS auto115_config (
                    user_id TEXT PRIMARY KEY,
                    main_cookies TEXT,
                    sub_accounts TEXT,
                    schedule_time TEXT DEFAULT '08:00'
                )''')
            
            conn.commit()
    except Exception as e:
        logging.error(f"数据库初始化失败: {str(e)}")
        raise

# ------------------- 核心功能路由 -------------------
@app.route('/')
def index():
    """主页面"""
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    """用户登录"""
    try:
        data = request.json
        passport = data.get('passport')
        password = data.get('password')
        
        user_info = get_user_info_with_password(passport, password)
        if user_info.get("code") != 0:
            return jsonify({"success": False, "message": user_info.get("message", "登录失败")})

        # 保存用户信息到会话
        session['logged_in'] = True
        session['user_info'] = {
            'uid': user_info['data']['uid'],
            'nickname': user_info['data']['nickname'],
            'passport': user_info['data']['passport'],
            'spaceUsed': user_info['data']['spaceUsed'],
            'spacePermanent': user_info['data']['spacePermanent']
        }
        return jsonify({"success": True})
    except Exception as e:
        logging.error(f"登录失败: {str(e)}")
        return jsonify({"success": False, "message": "服务器错误"})

@app.route('/user_info')
def get_user_info():
    """获取用户登录状态"""
    if not session.get('logged_in'):
        return jsonify({"logged_in": False})
    return jsonify({
        "logged_in": True,
        "user_info": session['user_info']
    })

@app.route('/logout')
def logout():
    """用户登出"""
    session.clear()
    return jsonify({"success": True})

# ------------------- 115配置管理路由 -------------------
@app.route('/115_config', methods=['GET', 'POST'])
def handle_115_config():
    """115配置管理"""
    if not session.get('logged_in'):
        return jsonify({"success": False})
    
    user_id = session['user_info']['uid']
    
    if request.method == 'POST':
        data = request.json
        try:
            with sqlite3.connect(CACHE_DB) as conn:
                conn.execute('''
                    REPLACE INTO auto115_config 
                    (user_id, main_cookies, sub_accounts, schedule_time)
                    VALUES (?, ?, ?, ?)
                ''', (
                    user_id,
                    json.dumps(data.get('main')),
                    json.dumps(data.get('subs')),
                    data.get('schedule', '08:00')
                ))
            return jsonify({"success": True})
        except Exception as e:
            logging.error(f"配置保存失败: {str(e)}")
            return jsonify({"success": False, "message": "配置保存失败"})
    else:
        try:
            with sqlite3.connect(CACHE_DB) as conn:
                row = conn.execute('''
                    SELECT main_cookies, sub_accounts, schedule_time 
                    FROM auto115_config WHERE user_id = ?
                ''', (user_id,)).fetchone()
            
            if row:
                return jsonify({
                    "main": json.loads(row[0]),
                    "subs": json.loads(row[1]),
                    "schedule_time": row[2]
                })
            return jsonify({})
        except Exception as e:
            logging.error(f"配置读取失败: {str(e)}")
            return jsonify({})

@app.route('/115_run_now', methods=['POST'])
def run_115_now():
    """立即执行115任务"""
    if not session.get('logged_in'):
        return jsonify({"success": False})
    
    try:
        user_id = session['user_info']['uid']
        # 使用 subprocess 启动 115_auto.py
        subprocess.Popen([
            'python', '/app/115_auto.py',
            '--config', f"/app/cache/config/115_{user_id}.json"
        ])
        return jsonify({"success": True})
    except Exception as e:
        logging.error(f"立即执行失败: {str(e)}")
        return jsonify({"success": False})

# ------------------- 日志管理路由 -------------------
@app.route('/log', methods=['POST'])
def handle_log():
    """接收日志并存储"""
    data = request.json
    if data and "message" in data:
        log_store.append(data["message"])
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "无效的日志数据"}), 400

@app.route('/get_logs', methods=['GET'])
def get_logs():
    """获取存储的日志"""
    return jsonify({"logs": list(log_store)})

@app.route('/get_local_logs', methods=['GET'])
def get_local_logs():
    """读取本地日志文件并返回日志内容"""
    log_file = os.getenv("LOG_FILE", "/app/cache/config/115_auto.log")
    try:
        if not os.path.exists(log_file):
            return jsonify({"logs": ["日志文件不存在"]})  # 返回空日志或提示信息
        with open(log_file, "r", encoding="utf-8") as f:
            logs = f.readlines()
        return jsonify({"logs": logs})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# ------------------- 初始化逻辑 -------------------
@app.before_first_request
def startup_event():
    """初始化任务"""
    init_db()
