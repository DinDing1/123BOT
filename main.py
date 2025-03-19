from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse
from p123 import P123Client, check_response
import os
import logging
import sqlite3
from datetime import datetime, timedelta
import hashlib
import json

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# 禁用冗余日志
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").disabled = True
logging.getLogger("uvicorn.error").disabled = True
logging.getLogger("fastapi").setLevel(logging.WARNING)
logging.getLogger("p123").setLevel(logging.WARNING)

# 数据库配置
CACHE_DB = "/app/cache/download_cache.db"
CACHE_TTL = 20 * 60 * 60  # 20小时

# 配置文件路径
CONFIG_FILE = "/app/cache/config/115_config.json"

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
            conn.commit()
    except Exception as e:
        logging.error(f"数据库初始化失败: {str(e)}")
        raise

def load_config():
    """加载配置文件"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"加载配置文件失败: {str(e)}")
        return None

def save_config(config):
    """保存配置文件"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        logging.error(f"保存配置文件失败: {str(e)}")
        return False

app = FastAPI(docs_url=None, redoc_url=None)

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
                logging.info(f"缓存命中 - {file_name}")
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
        
        logging.info(f"302重定向 - {file_name}")
        return RedirectResponse(download_url, status_code=302)

    except HTTPException as he:
        logging.warning(f"请求错误[{he.status_code}]: {he.detail}")
        raise
    except Exception as e:
        logging.error(f"服务器错误: {str(e)}", exc_info=True)
        raise HTTPException(500, "内部服务器错误")

@app.on_event("startup")
def startup_event():
    init_db()

logger = logging.getLogger('strm_generator')
logger.info("=== 302直连服务已启动 ===")
logger.info("302直连地址: http://0.0.0.0:8123")
