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
from flask_cors import CORS
from flask import Flask, request, jsonify
from collections import deque

# 日志存储（使用 deque 限制最大日志条数）
log_store = deque(maxlen=1000)  # 最多存储 1000 条日志

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
CORS(app, supports_credentials=True)  # 添加此行
app.secret_key = os.urandom(24)  # 确保 secret_key 已设置

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

def execute_115_job(user_id: str):
    """执行指定用户的115任务"""
    try:
        with sqlite3.connect(CACHE_DB) as conn:
            row = conn.execute('''
                SELECT main_cookies, sub_accounts 
                FROM auto115_config WHERE user_id = ?
            ''', (user_id,)).fetchone()
        
        if not row:
            logger.error(f"未找到用户配置: {user_id}")
            return

        config = {
            "wish_main": {
                "cookies": json.loads(row[0]),
                "name": "主账号"
            },
            "wish_subs": [
                {"cookies": json.loads(cookie), "name": f"小号{i}"} 
                for i, cookie in enumerate(json.loads(row[1]))
            ]
        }
        
        # 确保配置文件目录存在
        config_dir = "/app/cache"
        os.makedirs(config_dir, exist_ok=True)
        
        config_path = f"{config_dir}/115_{user_id}.json"
        with open(config_path, "w") as f:
            json.dump(config, f, ensure_ascii=False)
        
        subprocess.Popen([
            'python', '/app/115_auto.py',
            '--config', config_path
        ])
        logger.info(f"已启动115自动化任务 for user {user_id}")
    except Exception as e:
        logger.error(f"115任务执行失败: {str(e)}")

def run_115_task():
    """动态创建定时任务"""
    try:
        with sqlite3.connect(CACHE_DB) as conn:
            users = conn.execute('''
                SELECT user_id, schedule_time 
                FROM auto115_config
            ''').fetchall()

        scheduler = BackgroundScheduler()
        for user_id, schedule in users:
            if not schedule:
                schedule = "08:00"
            hour, minute = schedule.split(":")
            scheduler.add_job(
                execute_115_job,
                'cron',
                hour=int(hour),
                minute=int(minute),
                args=[user_id]
            )
        scheduler.start()
        logger.info("定时任务调度完成")
    except Exception as e:
        logger.error(f"定时任务创建失败: {str(e)}")

@app.before_first_request
def startup_event():
    """在第一个请求到达时初始化任务"""
    init_db()
    run_115_task()  # 启动时初始化定时任务



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

logger = logging.getLogger('strm_generator')
logger.info("=== WEBUI已启动 ===")
logger.info("WEBUI地址: http://0.0.0.0:8124")
