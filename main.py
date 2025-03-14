from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse
from p123 import P123Client, check_response
import os
import logging
import sqlite3
from datetime import datetime, timedelta
import hashlib
from apscheduler.schedulers.background import BackgroundScheduler

# 日志配置（简化格式）
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# 禁用 Uvicorn 的默认日志
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").disabled = True  # 禁用访问日志

# 数据库配置
CACHE_DB = "/app/cache/download_cache.db"
CACHE_TTL = 20 * 60 * 60  # 20小时

def init_db():
    """初始化数据库结构"""
    try:
        with sqlite3.connect(CACHE_DB) as conn:
            # 创建主表（含索引优化）
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
            
            # 创建自动清理触发器
            conn.execute('''
                CREATE TRIGGER IF NOT EXISTS auto_clean 
                AFTER INSERT ON download_cache
                BEGIN
                    DELETE FROM download_cache 
                    WHERE expire_time <= strftime('%Y-%m-%d %H:%M:%S', 'now');
                END;
            ''')
            conn.commit()
            logger.info("数据库初始化完成")
    except Exception as e:
        logger.error(f"数据库初始化失败: {str(e)}")
        raise

# 客户端初始化
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

# 维护任务优化
def db_optimize():
    try:
        with sqlite3.connect(CACHE_DB) as conn:
            conn.execute("PRAGMA optimize")
            conn.execute("VACUUM")
            logger.info("数据库优化完成")
    except Exception as e:
        logger.error(f"优化失败: {str(e)}")

@app.on_event("startup")
def startup_event():
    init_db()
    scheduler = BackgroundScheduler()
    scheduler.add_job(db_optimize, 'interval', hours=6)
    scheduler.start()
    # 仅保留关键启动日志
    logger.info("\n=== 302直连服务已启动 ===")
    logger.info(f"302直连地址: http://0.0.0.0:8123\n")

# 工具函数
def generate_cache_key(file_name: str, size: int, etag: str) -> str:
    """生成唯一缓存键"""
    raw_key = f"{file_name}|{size}|{etag}"
    return hashlib.sha256(raw_key.encode()).hexdigest()

# 核心路由
@app.get("/{uri:path}")
@app.head("/{uri:path}")
async def handle_request(request: Request, uri: str):
    try:
        # 参数解析
        if uri.count("|") < 2:
            raise HTTPException(400, "URI格式错误")
        
        file_name, size, etag_part = uri.rsplit("|", 2)
        etag = etag_part.split("?")[0]
        size = int(size)
        cache_key = generate_cache_key(file_name, size, etag)

        # 缓存查询（含有效期判断）
        with sqlite3.connect(CACHE_DB) as conn:
            cursor = conn.execute(
                '''
                SELECT url 
                FROM download_cache 
                WHERE 
                    key = ? 
                    AND expire_time > strftime('%Y-%m-%d %H:%M:%S', 'now')
                ''',
                (cache_key,)
            )
            if row := cursor.fetchone():
                logger.info(f"缓存命中 - {file_name}")
                return RedirectResponse(row[0], status_code=302)

        # 获取新地址
        download_resp = check_response(client.download_info({
            "FileName": file_name,
            "Size": size,
            "Etag": etag,
            "S3KeyFlag": request.query_params.get("s3keyflag", "")
        }))
        
        # 写入缓存
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
