from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse
from p123 import P123Client, check_response
import os
import logging
import sqlite3
from datetime import datetime, timedelta
import hashlib
from apscheduler.schedulers.background import BackgroundScheduler
import json
import subprocess

# 配置日志（简化格式，去除多余空行）
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
                CREATE INDEX IF NOT EXISTS idx_expire 
                ON download_cache (expire_time)
            ''')
            conn.execute('''
                CREATE TRIGGER IF NOT EXISTS auto_clean 
                AFTER INSERT ON download_cache
                BEGIN
                    DELETE FROM download_cache 
                    WHERE expire_time <= strftime('%Y-%m-%d %H:%M:%S', 'now');
                END;
            ''')
            conn.execute('DROP TABLE IF EXISTS auto115_config')  # 删除旧表
            conn.execute('''
                CREATE TABLE auto115_config (
                    user_id TEXT PRIMARY KEY,
                    main_cookies TEXT,
                    sub_accounts TEXT,
                    wish_content TEXT DEFAULT '求一本钢铁是怎样炼成得书',
                    schedule_time TEXT DEFAULT '08:00'
                )''')
            conn.commit()
            logger.info("数据库初始化完成")
    except Exception as e:
        logger.error(f"数据库初始化失败: {str(e)}")
        raise

try:
    client = P123Client(
        passport=os.getenv("P123_PASSPORT"),
        password=os.getenv("P123_PASSWORD")
    )
    client.login()
except Exception as e:
    logger.error(f"客户端初始化失败: {str(e)}")
    raise RuntimeError("客户端初始化失败")

app = FastAPI(docs_url=None, redoc_url=None)

def db_optimize():
    try:
        with sqlite3.connect(CACHE_DB) as conn:
            conn.execute("PRAGMA optimize")
            conn.execute("VACUUM")
            logger.info("数据库优化完成")
    except Exception as e:
        logger.error(f"优化失败: {str(e)}")

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
            "wish_subs": [{"cookies": json.loads(cookie)} for cookie in json.loads(row[1])]
        }
        
        config_path = f"/app/cache/115_{str(user_id)}.json"  # 强制转换为字符串
        with open(config_path, "w") as f:
            json.dump(config, f)
        
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

@app.on_event("startup")
def startup_event():
    init_db()
    scheduler = BackgroundScheduler()
    scheduler.add_job(db_optimize, 'interval', hours=6)
    scheduler.add_job(run_115_task)  # 启动时初始化定时任务
    scheduler.start()

def generate_cache_key(file_name: str, size: int, etag: str) -> str:
    raw_key = f"{file_name}|{size}|{etag}"
    return hashlib.sha256(raw_key.encode()).hexdigest()

@app.get("/{uri:path}")
@app.head("/{uri:path}")
async def handle_request(request: Request, uri: str):
    try:
        if uri.count("|") < 2:
            raise HTTPException(400, "URI格式错误")
        
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
                logger.info(f"缓存命中 - {file_name}")
                return RedirectResponse(row[0], status_code=302)

        download_resp = check_response(client.download_info({
            "FileName": file_name,
            "Size": size,
            "Etag": etag,
            "S3KeyFlag": request.query_params.get("s3keyflag", "")
        }))
        
        download_url = download_resp["data"]["DownloadUrl"]
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
        
        logger.info(f"302重定向 - {file_name}")
        return RedirectResponse(download_url, status_code=302)

    except HTTPException as he:
        logger.warning(f"请求错误[{he.status_code}]: {he.detail}")
        raise
    except Exception as e:
        logger.error(f"服务器错误: {str(e)}", exc_info=True)
        raise HTTPException(500, "内部服务器错误")

logger = logging.getLogger('strm_generator')
logger.info("=== 302直连服务已启动 ===")
logger.info("302直连地址: http://0.0.0.0:8123")
