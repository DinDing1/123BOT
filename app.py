from flask import Flask, render_template, request, jsonify, Response, stream_with_context, session
import subprocess
import os
import logging
import sqlite3
from datetime import datetime, timedelta
import hashlib
from apscheduler.schedulers.background import BackgroundScheduler
import json
from auth import get_user_info_with_password
from werkzeug.serving import WSGIRequestHandler

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# 禁用 Uvicorn 和 FastAPI 的默认日志
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").disabled = True
logging.getLogger("uvicorn.error").disabled = True
logging.getLogger("fastapi").setLevel(logging.WARNING)
logging.getLogger("apscheduler").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("p123").setLevel(logging.WARNING)

# 数据库配置
CACHE_DB = "/app/cache/download_cache.db"
CACHE_TTL = 20 * 60 * 60  # 20小时

def init_db():
    """初始化数据库结构"""
    try:
        with sqlite3.connect(CACHE_DB) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS download_cache (
                    key TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    expire_time TIMESTAMP NOT NULL
                )''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS auto115_config (
                    user_id TEXT PRIMARY KEY,
                    main_cookies TEXT,
                    sub_accounts TEXT,
                    schedule_time TEXT DEFAULT '08:00'
                )''')
            conn.commit()
            logger.info("数据库初始化完成")
    except Exception as e:
        logger.error(f"数据库初始化失败: {str(e)}")
        raise

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/')
def index():
    return render_template('index.html')

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

@app.route('/115_config', methods=['GET', 'POST'])
def handle_115_config():
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
    if not session.get('logged_in'):
        return jsonify({"success": False})
    
    try:
        user_id = session['user_info']['uid']
        subprocess.Popen([
            'python', '/app/115_auto.py',
            '--config', f"/app/cache/115_{user_id}.json"
        ])
        return jsonify({"success": True})
    except Exception as e:
        logging.error(f"立即执行失败: {str(e)}")
        return jsonify({"success": False})

@app.on_event("startup")
def startup_event():
    init_db()
    scheduler = BackgroundScheduler()
    scheduler.add_job(run_115_task)  # 启动时初始化定时任务
    scheduler.start()

logger = logging.getLogger('strm_generator')
logger.info("=== WEBUI已启动 ===")
logger.info("WEBUI地址: http://0.0.0.0:8124")
