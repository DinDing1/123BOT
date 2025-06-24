import warnings
warnings.filterwarnings("ignore", message="python-telegram-bot is using upstream urllib3.*")
warnings.filterwarnings("ignore", message=".*pkg_resources is deprecated.*", category=UserWarning)
import os
import re
import json
import time
import logging
import requests
import sqlite3
import threading
import traceback
import urllib.parse
from contextlib import closing
from datetime import datetime, timedelta, timezone
from telegram import Update, BotCommand, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Updater, 
    MessageHandler, 
    Filters, 
    CallbackContext, 
    CommandHandler,
    CallbackQueryHandler
)
from functools import wraps
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from collections import defaultdict, deque
from typing import Dict, Optional, List, Tuple

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

######################版本信息###########
def get_version():
    """从 VERSION 文件中读取版本号"""
    version_file = "/app/VERSION"
    if os.path.exists(version_file):
        with open(version_file, "r", encoding="utf-8") as f:
            return f.read().strip()
    return "未知版本"

VERSION = get_version()
#######################################

# 配置日志
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 忽略第三方库的警告
logging.getLogger("telegram").setLevel(logging.WARNING)
logging.getLogger("apscheduler").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("p115").setLevel(logging.WARNING)
logging.getLogger("p115client").setLevel(logging.WARNING)

# ====================== 配置区域 ======================
# 数据库文件路径
DB_PATH = os.getenv("DB_PATH", "bot123.db")

# 123云盘API配置
PAN_HOST = "https://www.123pan.com"
API_PATHS = {
    "TOKEN": "/api/v1/access_token",
    "USER_INFO": "/api/v1/user/info",
    "LIST_FILES_V2": "/api/v2/file/list",
    "UPLOAD_REQUEST": "/b/api/file/upload_request",
    "CLEAR_TRASH": "/api/file/trash_delete_all",
    "GET_SHARE": "/b/api/share/get",
    "OFFLINE_DOWNLOAD": "/api/v1/offline/download",
    "DIRECTORY_CREATE": "/upload/v1/file/mkdir",
    "DOWNLOAD_PROGRESS": "/api/v1/offline/download/process"
}

# 开放平台地址
OPEN_API_HOST = "https://open-api.123pan.com"

# 秒传链接前缀
LEGACY_FOLDER_LINK_PREFIX_V1 = "123FSLinkV1$"
LEGACY_FOLDER_LINK_PREFIX_V2 = "123FSLinkV2$"
COMMON_PATH_LINK_PREFIX_V1 = "123FLCPV1$"
COMMON_PATH_LINK_PREFIX_V2 = "123FLCPV2$"
COMMON_PATH_DELIMITER = "%"

# Base62字符集
BASE62_CHARS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

# 环境变量配置
DEFAULT_SAVE_DIR = os.getenv("DEFAULT_SAVE_DIR", "").strip()
EXPORT_BASE_DIRS = [d.strip() for d in os.getenv("EXPORT_BASE_DIR", "").split(';') if d.strip()]
SEARCH_MAX_DEPTH = int(os.getenv("SEARCH_MAX_DEPTH", ""))
DAILY_EXPORT_LIMIT = int(os.getenv("DAILY_EXPORT_LIMIT", "3")) #导出次数
BANNED_EXPORT_NAMES = [name.strip().lower() for name in os.getenv("BANNED_EXPORT_NAMES", "电视剧;电影").split(';') if name.strip()]

# API速率控制配置
API_RATE_LIMIT = float(os.getenv("API_RATE_LIMIT", "2.0"))
TRANSFER_RATE_LIMIT = float(os.getenv("TRANSFER_RATE_LIMIT", "3"))

# 允许的文件类型配置
ALLOWED_VIDEO_EXTENSIONS = [ext.strip().lower() for ext in os.getenv("ALLOWED_VIDEO_EXT", ".mp4,.mkv,.avi,.mov,.flv,.wmv,.webm,.ts,.m2ts,.iso,.mp3,.flac,.wav").split(',') if ext.strip()]
ALLOWED_SUB_EXTENSIONS = [ext.strip().lower() for ext in os.getenv("ALLOWED_SUB_EXT", ".srt,.ass,.ssa,.sub,.idx,.vtt,.sup").split(',') if ext.strip()]
# 合并所有允许的文件类型
ALLOWED_EXTENSIONS = ALLOWED_VIDEO_EXTENSIONS + ALLOWED_SUB_EXTENSIONS

# 115网盘配置
COOKIES_115 = os.getenv("COOKIES_115", "")
CUSTOM_DIRECT_LINK_SERVICE = os.getenv("CUSTOM_DIRECT_LINK_SERVICE", "")
TARGET_PATH_115 = os.getenv("TARGET_PATH_115", "")
DELETE_AFTER_TRANSFER = os.getenv("DELETE_AFTER_TRANSFER", "true").lower() == "true"

# 任务状态映射
TASK_STATUS_MAP = {
    0: "进行中",
    1: "下载失败",
    2: "下载成功",
    3: "重试中"
}
# =====================================================

def init_db():
    """初始化数据库"""
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            # 创建所有表
            tables = [
                '''CREATE TABLE IF NOT EXISTS token_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    access_token TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    client_secret TEXT NOT NULL,
                    expired_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS directory_cache (
                    file_id INTEGER PRIMARY KEY,
                    filename TEXT NOT NULL,
                    parent_id INTEGER NOT NULL,
                    full_path TEXT NOT NULL,
                    base_dir_id INTEGER NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS user_privileges (
                    user_id INTEGER PRIMARY KEY,
                    privilege_level TEXT NOT NULL DEFAULT 'user',
                    export_count INTEGER NOT NULL DEFAULT 0,
                    last_export_date TIMESTAMP,
                    join_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS export_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    export_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    folder_count INTEGER NOT NULL
                )'''
            ]
            
            for table in tables:
                c.execute(table)
            
            # 创建索引
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_filename ON directory_cache (filename)",
                "CREATE INDEX IF NOT EXISTS idx_full_path ON directory_cache (full_path)",
                "CREATE INDEX IF NOT EXISTS idx_base_dir ON directory_cache (base_dir_id)"
            ]
            
            for index in indexes:
                c.execute(index)
                
            conn.commit()
    except Exception as e:
        logger.error(f"数据库初始化失败: {e}")

init_db()

# ====================== 工具函数 ======================
def format_size(size_bytes):
    """格式化文件大小"""
    if size_bytes >= 1024 ** 4:
        return f"{size_bytes / (1024 ** 4):.2f} TB"
    elif size_bytes >= 1024 ** 3:
        return f"{size_bytes / (1024 ** 3):.2f} GB"
    elif size_bytes >= 1024 ** 2:
        return f"{size_bytes / (1024 ** 2):.2f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f} KB"
    else:
        return f"{size_bytes} bytes"

def generate_usage_bar(percent, length=20):
    """生成使用率进度条"""
    filled = int(round(length * percent / 100))
    empty = length - filled
    return "[" + "█" * filled + "░" * empty + "]"

# =====================================================

class TokenManager:
    """管理API token的获取和缓存"""
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret
        self.session = self._create_session()
        self.access_token = None
        self.token_expiry = None
        self.start_time = datetime.now()
        
        if not self.load_token_from_cache():
            self.get_new_token()
    
    def _create_session(self):
        """创建带重试机制的Session"""
        session = requests.Session()
        retry_strategy = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.verify = False
        return session
    
    def load_token_from_cache(self):
        """从数据库加载缓存的Token"""
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                c.execute("SELECT access_token, client_id, client_secret, expired_at FROM token_cache ORDER BY id DESC LIMIT 1")
                row = c.fetchone()
                
                if row:
                    token, cached_id, cached_secret, expired_at_str = row
                    expired_at = datetime.fromisoformat(expired_at_str).astimezone(timezone.utc)
                    now = datetime.now(timezone.utc)
                    
                    if (expired_at > now + timedelta(minutes=5) and \
                       self.client_id == cached_id and \
                       self.client_secret == cached_secret):
                        self.access_token = token
                        self.token_expiry = expired_at
                        logger.info("使用缓存Token")
                    
                        return True
        except Exception as e:
            logger.error(f"加载Token缓存失败: {e}")
        return False
    
    def save_token_to_cache(self, access_token, expired_at):
        """保存Token到数据库"""
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                c.execute("DELETE FROM token_cache")
                c.execute('''INSERT INTO token_cache 
                           (access_token, client_id, client_secret, expired_at)
                           VALUES (?,?,?,?)''',
                           (access_token, self.client_id, self.client_secret, expired_at.isoformat()))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"保存Token到缓存失败: {e}")
            return False
    
    def get_new_token(self):
        """获取新token"""
        try:
            logger.info("正在获取新Token...")
            url = f"{OPEN_API_HOST}{API_PATHS['TOKEN']}"
            payload = {
                "clientID": self.client_id,
                "clientSecret": self.client_secret
            }
            
            headers = {
                "Content-Type": "application/json",
                "Platform": "open_platform"
            }
            
            response = self.session.post(url, json=payload, headers=headers, timeout=20)
            
            if response.status_code != 200:
                logger.error(f"认证失败: HTTP {response.status_code}")
                return False
            
            data = response.json()
            if data.get("code") != 0:
                logger.error(f"API错误: {data.get('code')} - {data.get('message')}")
                return False
            
            self.access_token = data["data"]["accessToken"]
            expired_at_str = data["data"]["expiredAt"]
            
            # 统一处理时间格式
            if expired_at_str.endswith('Z'):
                expired_at_str = expired_at_str[:-1] + "+00:00"
            
            self.token_expiry = datetime.fromisoformat(expired_at_str).astimezone(timezone.utc)
            
            if self.save_token_to_cache(self.access_token, self.token_expiry):
                logger.info(f"更新Token成功，有效期至: {self.token_expiry} (UTC)")
                return True
            return False
        except Exception as e:
            logger.error(f"获取Token失败: {e}")
            return False
    
    def ensure_token_valid(self):
        """确保token有效"""
        current_time = datetime.now(timezone.utc)
        if not self.access_token or not self.token_expiry or current_time >= self.token_expiry - timedelta(minutes=5):
            logger.info("Token无效或即将过期，刷新中...")
            return self.get_new_token()
        return True
    
    def get_auth_header(self):
        """获取认证头"""
        if not self.ensure_token_valid():
            raise Exception("无法获取有效的Token")
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Platform": "open_platform",
            "Content-Type": "application/json"
        }
        
def is_allowed_file(filename):
    """检查文件是否为允许的类型"""
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_VIDEO_EXTENSIONS or ext in ALLOWED_SUB_EXTENSIONS

class Pan123Client:
    def __init__(self, client_id, client_secret):
        self.token_manager = TokenManager(client_id, client_secret)
        self.session = self._create_session()
        self.last_api_call = 0
        self.api_rate_limit = API_RATE_LIMIT
        self.share_root_folder = ""
        
        # 初始化目录ID
        self.default_save_dir_id = 0
        self.export_base_dir_ids = []
        self.export_base_dir_map = {0: "根目录"}
        
        # API速率控制
        self.rate_limit_lock = threading.Lock()
        
        if DEFAULT_SAVE_DIR:
            self.default_save_dir_id = self.get_or_create_directory(DEFAULT_SAVE_DIR)
            logger.info(f"默认保存目录已设置: '{DEFAULT_SAVE_DIR}' (ID: {self.default_save_dir_id})")
        
        for base_dir in EXPORT_BASE_DIRS:
            base_dir_id = self.get_or_create_directory(base_dir)
            self.export_base_dir_ids.append(base_dir_id)
            self.export_base_dir_map[base_dir_id] = base_dir
            logger.info(f"导出基目录已设置: '{base_dir}' (ID: {base_dir_id})")
        
        self.search_max_depth = SEARCH_MAX_DEPTH
        logger.info(f"搜索最大深度已设置: {self.search_max_depth} 层")
        
        # 初始化目录缓存
        self.directory_cache = {}
        self.load_directory_cache()
        logger.info(f"已加载 {len(self.directory_cache)} 个目录缓存")
    
    def _create_session(self):
        """创建带重试机制的Session"""
        session = requests.Session()
        session.trust_env = False
        retry_strategy = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.verify = False
        return session
    
    def get_or_create_directory(self, path):
        """获取或创建目录路径"""
        parent_id = 0
        parts = path.strip('/').split('/')
        
        for part in parts:
            if not part:
                continue
                
            folder_info = self.search_folder(part, parent_id)
            if folder_info:
                parent_id = folder_info["fileId"]
                logger.debug(f"找到目录: '{part}' (ID: {parent_id})")
            else:
                logger.info(f"创建目录: '{part}' (父ID: {parent_id})")
                folder = self.create_folder(parent_id, part)
                if folder:
                    parent_id = folder["FileId"]
                    logger.info(f"已创建目录: '{part}' (ID: {parent_id})")
        
        return parent_id
    
    def search_folder(self, folder_name, parent_id=0):
        """在指定父目录下搜索文件夹"""
        try:
            url = f"{OPEN_API_HOST}{API_PATHS['LIST_FILES_V2']}"
            params = {
                "parentFileId": parent_id,
                "trashed": 0,
                "limit": 100,
                "lastFileId": 0
            }
            headers = self.token_manager.get_auth_header()
            
            response = self._call_api("GET", url, params=params, headers=headers, timeout=30)
            if not response or response.status_code != 200:
                return None
                
            data = response.json()
            if data.get("code") != 0:
                return None
                
            for item in data["data"].get("fileList", []):
                if item["type"] == 1 and item["filename"] == folder_name:
                    return {
                        "fileId": item["fileId"],
                        "filename": item["filename"]
                    }
        except Exception as e:
            logger.error(f"搜索目录出错: {e}")
        return None

    def _call_api(self, method, url, **kwargs):
        """控制API调用频率，添加最大重试次数限制"""
        retry_count = 0
        max_retries = 5
        
        while retry_count < max_retries:
            try:
                with self.rate_limit_lock:
                    elapsed = time.time() - self.last_api_call
                    required_delay = 1.0 / self.api_rate_limit
                    if elapsed < required_delay:
                        time.sleep(required_delay - elapsed)
                    response = self.session.request(method, url, **kwargs)
                    self.last_api_call = time.time()
                
                if response.status_code == 429:
                    retry_after = response.headers.get('Retry-After')
                    wait_time = float(retry_after) if retry_after else 5.0
                    logger.warning(f"API限流，等待 {wait_time} 秒后重试...")
                    time.sleep(wait_time)
                    retry_count += 1
                    continue
                
                try:
                    data = response.json()
                    if data.get("code") == 429 or "操作频繁" in data.get("message", ""):
                        logger.warning("API限流（内容检测），等待5秒后重试...")
                        time.sleep(5.0)
                        retry_count += 1
                        continue
                except:
                    pass
                
                return response
                
            except (requests.exceptions.SSLError, 
                    requests.exceptions.ConnectionError,
                    requests.exceptions.ChunkedEncodingError,
                    requests.exceptions.HTTPError) as e:
                retry_count += 1
                logger.error(f"网络连接错误: {e}，重试 {retry_count}/{max_retries}")
                time.sleep(2 ** retry_count)
            except Exception as e:
                logger.error(f"API调用出错: {e}")
                retry_count += 1
                time.sleep(2 ** retry_count)
        
        logger.error(f"API调用失败，已达到最大重试次数 {max_retries}")
        return None
    
    def _get_auth_headers(self):
        """获取认证头"""
        auth_header = self.token_manager.get_auth_header()
        return {
            **auth_header,
            "platform": "web",
            "App-Version": "3",
            "Origin": PAN_HOST,
            "Referer": f"{PAN_HOST}/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
        }
    
    def get_user_info(self):
        """获取用户信息"""
        try:
            if not self.token_manager.ensure_token_valid():
                return None
                
            url = f"{OPEN_API_HOST}{API_PATHS['USER_INFO']}"
            headers = self.token_manager.get_auth_header()
            response = self._call_api("GET", url, headers=headers, timeout=30)
            if not response or response.status_code != 200:
                return None
                
            data = response.json()
            if data.get("code") != 0:
                return None
                
            return data.get("data")
        except Exception as e:
            logger.error(f"获取用户信息出错: {e}")
            return None
    
    def create_folder(self, parent_id, folder_name, retry_count=3):
        """创建文件夹"""
        for attempt in range(retry_count):
            try:
                url = f"{PAN_HOST}{API_PATHS['UPLOAD_REQUEST']}"
                payload = {
                    "driveId": 0,
                    "etag": "",
                    "fileName": folder_name,
                    "parentFileId": int(parent_id),
                    "size": 0,
                    "type": 1,
                    "NotReuse": True,
                    "RequestSource": None,
                    "duplicate": 1,
                    "event": "newCreateFolder",
                    "operateType": 1
                }
                headers = self._get_auth_headers()
                response = self.session.post(url, json=payload, headers=headers, timeout=20, verify=False)
                data = response.json()
                
                if data.get("code") == 0 and data["data"].get("Info", {}).get("FileId"):
                    folder_id = data["data"]["Info"]["FileId"]
                    logger.info(f"文件夹创建成功: '{folder_name}' (ID: {folder_id})")
                    return data["data"]["Info"]
                else:
                    error_msg = data.get("message", "未知错误")
                    logger.error(f"创建文件夹失败: {error_msg}")
            except Exception as e:
                logger.error(f"创建文件夹过程中出错: {e}")
            time.sleep(1)
        return None
    
    def rapid_upload(self, etag, size, file_name, parent_id, max_retries=8):
        """秒传文件"""
        original_etag = etag
        
        if len(etag) != 32 or not all(c in '0123456789abcdef' for c in etag.lower()):
            etag = FastLinkProcessor.optimized_etag_to_hex(etag, True)
        
        base_delay = 2.0
        max_delay = 180.0
        
        for attempt in range(max_retries):
            try:
                delay = min(max_delay, base_delay * (2 ** attempt))
                if attempt > 0:
                    time.sleep(delay)
                
                url = f"{PAN_HOST}{API_PATHS['UPLOAD_REQUEST']}"
                payload = {
                    "driveId": 0,
                    "etag": etag,
                    "fileName": file_name,
                    "parentFileId": int(parent_id),
                    "size": int(size),
                    "type": 0,
                    "NotReuse": False,
                    "RequestSource": None,
                    "duplicate": 1,
                    "event": "rapidUpload",
                    "operateType": 1
                }
                headers = self._get_auth_headers()
                response = self._call_api("POST", url, json=payload, headers=headers, timeout=30)
                
                if not response:
                    continue
                
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    continue
                
                if data.get("code") == 0 and data["data"].get("Info", {}).get("FileId"):
                    file_id = data["data"]["Info"]["FileId"]
                    logger.info(f"文件秒传成功: '{file_name}' (ID: {file_id})")
                    return data["data"]["Info"]
                else:
                    error_msg = data.get("message", "未知错误")
                    logger.error(f"文件秒传失败: {error_msg}")
                    if "etag" in error_msg.lower() and etag != original_etag:
                        etag = original_etag
                        continue
                    if "操作频繁" in error_msg or "限流" in error_msg or "频繁" in error_msg:
                        with self.rate_limit_lock:
                            self.api_rate_limit = max(0.8, self.api_rate_limit * 0.9)
                        logger.warning(f"触发限流，降低全局速率至 {self.api_rate_limit:.2f} 请求/秒")
                        continue
            except Exception as e:
                logger.error(f"秒传过程中出错: {e}")
        logger.error(f"秒传失败，已达到最大重试次数 {max_retries}")
        return None
    
    def load_directory_cache(self):
        """从数据库加载目录缓存"""
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                
                if not self.export_base_dir_ids:
                    c.execute("SELECT * FROM directory_cache")
                else:
                    placeholders = ','.join(['?'] * len(self.export_base_dir_ids))
                    c.execute(f"SELECT * FROM directory_cache WHERE base_dir_id IN ({placeholders})", 
                              self.export_base_dir_ids)
                
                rows = c.fetchall()
                for row in rows:
                    file_id = row["file_id"]
                    self.directory_cache[file_id] = dict(row)
                logger.info(f"已加载 {len(rows)} 个目录缓存")
        except Exception as e:
            logger.error(f"加载目录缓存失败: {e}")
    
    def update_directory_cache(self, file_id, filename, parent_id, full_path, base_dir_id):
        """更新目录缓存"""
        try:
            if file_id in self.directory_cache:
                existing = self.directory_cache[file_id]
                if (existing["filename"] == filename and 
                    existing["parent_id"] == parent_id and 
                    existing["full_path"] == full_path and
                    existing["base_dir_id"] == base_dir_id):
                    return False
            
            cache_entry = {
                "file_id": file_id,
                "filename": filename,
                "parent_id": parent_id,
                "full_path": full_path,
                "base_dir_id": base_dir_id
            }
            self.directory_cache[file_id] = cache_entry
            
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                c.execute('''INSERT OR REPLACE INTO directory_cache 
                            (file_id, filename, parent_id, full_path, base_dir_id) 
                            VALUES (?,?,?,?,?)''',
                          (file_id, filename, parent_id, full_path, base_dir_id))
                conn.commit()
            logger.info(f"更新目录缓存: {filename} (ID: {file_id}, 路径: {full_path})")
            return True
        except Exception as e:
            logger.error(f"更新目录缓存失败: {e}")
            return False
    
    def full_sync_directory_cache(self):
        """全量同步目录缓存"""
        logger.info("开始全量同步目录缓存...")
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                c.execute("DELETE FROM directory_cache")
                c.execute("DELETE FROM sqlite_sequence WHERE name='directory_cache'")
                conn.commit()
                logger.info("已清空旧缓存数据表")

            self.directory_cache = {}
            update_count = 0
            
            for base_dir_id in self.export_base_dir_ids:
                base_dir_path = self.export_base_dir_map.get(base_dir_id, f"基目录({base_dir_id})")
                update_count += self.sync_directory(base_dir_id, base_dir_path, base_dir_id)
            
            logger.info(f"全量同步完成，更新 {update_count} 个目录")
            return update_count
        except Exception as e:
            logger.error(f"全量同步失败: {e}")
            return 0
    
    def sync_directory(self, directory_id, current_path, base_dir_id, current_depth=0):
        """同步指定目录及其子目录"""
        last_file_id = 0
        update_count = 0
        
        while True:
            url = f"{OPEN_API_HOST}{API_PATHS['LIST_FILES_V2']}"
            params = {
                "parentFileId": directory_id,
                "trashed": 0,
                "limit": 100,
                "lastFileId": last_file_id
            }
            headers = self.token_manager.get_auth_header()
            
            try:
                response = self._call_api("GET", url, params=params, headers=headers, timeout=30)
                if not response or response.status_code != 200:
                    break
                
                data = response.json()
                if data.get("code") != 0:
                    break
                
                for item in data["data"].get("fileList", []):
                    if item.get("trashed", 1) != 0:
                        continue
                    
                    item_path = f"{current_path}/{item['filename']}" if current_path else item['filename']
                    
                    if item["type"] == 1:
                        updated = self.update_directory_cache(
                            item["fileId"],
                            item["filename"],
                            directory_id,
                            item_path,
                            base_dir_id
                        )
                        if updated:
                            update_count += 1
                        
                        if current_depth < self.search_max_depth:
                            update_count += self.sync_directory(
                                item["fileId"],
                                item_path,
                                base_dir_id,
                                current_depth + 1
                            )
                
                last_file_id = data["data"].get("lastFileId", -1)
                if last_file_id == -1:
                    break
            except Exception as e:
                logger.error(f"同步目录出错: {e}")
                break
        
        return update_count
    
    def get_directory_files(self, directory_id=0, base_path="", current_path=""):
        """获取目录下的所有文件"""
        all_files = []
        
        if not self.token_manager.ensure_token_valid():
            return []
        
        last_file_id = 0
        while True:
            url = f"{OPEN_API_HOST}{API_PATHS['LIST_FILES_V2']}"
            params = {
                "parentFileId": directory_id,
                "trashed": 0,
                "limit": 100,
                "lastFileId": last_file_id
            }
            headers = self.token_manager.get_auth_header()
            
            try:
                response = self._call_api("GET", url, params=params, headers=headers, timeout=30)
                if not response or response.status_code != 200:
                    return all_files
                
                data = response.json()
                if data.get("code") != 0:
                    return all_files
                
                for item in data["data"].get("fileList", []):
                    if item.get("trashed", 1) != 0:
                        continue
                    
                    if current_path:
                        file_path = f"{current_path}/{item['filename']}"
                    else:
                        file_path = item['filename']
                    
                    if item["type"] == 0:
                        if not is_allowed_file(item['filename']):
                            continue
                        all_files.append({
                            "path": file_path,
                            "etag": item["etag"],
                            "size": item["size"]
                        })
                    elif item["type"] == 1:
                        if current_path:
                            sub_path = f"{current_path}/{item['filename']}"
                        else:
                            sub_path = item['filename']
                        time.sleep(0.5)
                        sub_files = self.get_directory_files(item["fileId"], base_path, sub_path)
                        all_files.extend(sub_files)
                
                last_file_id = data["data"].get("lastFileId", -1)
                if last_file_id == -1:
                    break
            except Exception as e:
                logger.error(f"获取目录列表出错: {e}")
                return all_files
        
        return all_files

    def clear_trash(self):
        """清空回收站"""
        try:
            url = f"{PAN_HOST}{API_PATHS['CLEAR_TRASH']}"
            headers = self._get_auth_headers()
            payload = {"event": "recycleClear"}
            response = self._call_api("POST", url, json=payload, headers=headers, timeout=30)
            if not response or response.status_code != 200:
                return False
            data = response.json()
            if data.get("code") == 7301 or data.get("code") == 0:
                logger.info("回收站已清空")
                return True
            return False
        except Exception as e:
            logger.error(f"清空回收站出错: {e}")
            return False
   
    def extract_share_info(self, share_url):
        """从分享链接提取分享Key和密码（使用改进的正则）"""
        pattern = r'(https?://(?:[a-zA-Z0-9-]+\.)*123[a-zA-Z0-9-]*\.[a-z]{2,6}+/s/)([a-zA-Z0-9\-_]+)(?:[\s\S]*?(?:提取码|密码|code)[\s:：=]*(\w{4}))?'
        match = re.search(pattern, share_url)
        if not match:
            raise ValueError("无效的分享链接格式")
        
        share_key = match.group(2)
        password = match.group(3) or ""
        
        return share_key, password

    def save_share_files(self, share_url, save_dir_id):
        """保存分享链接中的文件到指定目录，保留原始目录结构"""
        try:
            # 提取分享信息
            share_key, password = self.extract_share_info(share_url)
            
            # 递归获取所有文件
            files = self._get_share_files_recursive(share_key, password, "0", "")
            if not files:
                logger.warning("分享中没有文件")
                return 0, 0, [], 0
                
            # 用于存储目录映射：路径 -> 云盘目录ID
            dir_map = {"": save_dir_id}  # 根目录映射
            success_count = 0
            failure_count = 0
            results = []
            total_size = 0  # 统计总大小
            
            # 首先创建所有需要的目录
            all_dirs = {os.path.dirname(f["path"]) for f in files}
            for dir_path in sorted(all_dirs):
                if not dir_path or dir_path in dir_map:
                    continue
                    
                # 创建目录路径
                parent_id = save_dir_id
                parts = dir_path.split('/')
                current_path = ""
                
                for part in parts:
                    if not part:
                        continue
                        
                    current_path = f"{current_path}/{part}" if current_path else part
                    if current_path in dir_map:
                        parent_id = dir_map[current_path]
                        continue
                        
                    # 创建目录
                    folder = self.create_folder(parent_id, part)
                    if folder:
                        dir_map[current_path] = folder["FileId"]
                        parent_id = folder["FileId"]
                    else:
                        break
            
            # 转存文件
            for file_info in files:
                file_path = file_info["path"]
                file_name = os.path.basename(file_path)
                dir_path = os.path.dirname(file_path)
                parent_id = dir_map.get(dir_path, save_dir_id)
                
                # 只转存允许的文件类型
                if not is_allowed_file(file_name):
                    continue
                
                total_size += file_info["size"]
                
                try:
                    result = self.rapid_upload(
                        file_info["etag"], 
                        file_info["size"], 
                        file_name, 
                        parent_id
                    )
                    
                    if result:
                        success_count += 1
                        results.append({
                            "success": True,
                            "file_name": file_path,
                            "size": file_info["size"]
                        })
                    else:
                        failure_count += 1
                        results.append({
                            "success": False,
                            "file_name": file_path,
                            "size": file_info["size"],
                            "error": "秒传失败"
                        })
                except Exception as e:
                    failure_count += 1
                    results.append({
                        "success": False,
                        "file_name": file_path,
                        "size": file_info["size"],
                        "error": str(e)
                    })
            
            return success_count, failure_count, results, total_size
        except Exception as e:
            logger.error(f"保存分享文件失败: {e}")
            return 0, 0, [], 0
    
    def _get_share_files_recursive(self, share_key, password, fid, current_path):
        """递归获取分享中的所有文件"""
        files = []
        items = self._get_share_files(share_key, password, fid)
        
        for item in items:
            if item["Type"] == 0:  # 文件
                file_path = f"{current_path}/{item['FileName']}" if current_path else item['FileName']
                files.append({
                    "path": file_path,
                    "name": item["FileName"],
                    "size": item["Size"],
                    "etag": item["Etag"]
                })
            elif item["Type"] == 1:  # 目录
                sub_path = f"{current_path}/{item['FileName']}" if current_path else item['FileName']
                sub_files = self._get_share_files_recursive(
                    share_key, 
                    password, 
                    item["FileId"], 
                    sub_path
                )
                files.extend(sub_files)
        
        return files
    
    def _get_share_files(self, share_key, password, fid="0"):
        """获取分享中的文件和目录列表（非递归）"""
        items = []
        next_marker = "0"
        page = 1
        
        while next_marker != "-1":
            params = {
                "shareKey": share_key,
                "SharePwd": password,
                "parentFileId": fid,
                "limit": 100,
                "next": next_marker,
                "orderBy": "file_name",
                "orderDirection": "asc",
                "Page": page
            }
            
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                "Referer": f"{PAN_HOST}/s/{share_key}",
                "Origin": PAN_HOST
            }
            
            try:
                response = self._call_api("GET", f"{PAN_HOST}{API_PATHS['GET_SHARE']}", 
                                         params=params, headers=headers, timeout=30)
                if not response or response.status_code != 200:
                    break
                
                data = response.json()
                if data.get("code") != 0:
                    logger.warning(f"获取分享文件失败: {data.get('message', '未知错误')}")
                    break
                
                # 添加当前页的项目
                for item in data["data"]["InfoList"]:
                    item["Type"] = item.get("Type", 0)
                    items.append(item)
                
                # 检查是否有下一页
                next_marker = data["data"].get("Next", "-1")
                page += 1
                
            except Exception as e:
                logger.error(f"获取分享文件时出错: {e}")
                break
        
        return items
    
    # ====================== 115网盘功能 ======================
    def create_directory(self, parent_id, name):
        """在123云盘上创建目录"""
        headers = self.token_manager.get_auth_header()
        payload = {
            "parentID": parent_id,
            "name": name
        }
        
        try:
            url = f"{OPEN_API_HOST}{API_PATHS['DIRECTORY_CREATE']}"
            response = self._call_api("POST", url, json=payload, headers=headers)
            if not response or response.status_code != 200:
                return None
                
            data = response.json()
            if data.get("code") == 0:
                return data["data"]["dirID"]
            else:
                logger.error(f"创建目录失败: {data.get('message', '未知错误')}")
                return None
        except Exception as e:
            logger.error(f"创建目录异常: {e}")
            return None
    
    def list_directory(self, parent_id):
        """获取123云盘目录下的子目录列表"""
        headers = self.token_manager.get_auth_header()
        dirs = []
        last_file_id = 0
        
        while True:
            params = {
                "parentFileId": parent_id,
                "trashed": 0,
                "limit": 100,
                "lastFileId": last_file_id
            }
            
            try:
                url = f"{OPEN_API_HOST}{API_PATHS['LIST_FILES_V2']}"
                response = self._call_api("GET", url, params=params, headers=headers)
                if not response or response.status_code != 200:
                    break
                
                data = response.json()
                if data.get("code") != 0:
                    logger.error(f"获取目录列表失败: {data.get('message', '未知错误')}")
                    break
                
                for item in data["data"].get("fileList", []):
                    if item["type"] == 1 and item.get("trashed", 0) == 0:
                        dirs.append({
                            "id": item["fileId"],
                            "name": item["filename"]
                        })
                
                last_file_id = data["data"].get("lastFileId", -1)
                if last_file_id == -1:
                    break
            except Exception as e:
                logger.error(f"获取目录列表异常: {e}")
                break
        
        return dirs
    
    def ensure_directory(self, parent_id, dir_name):
        """确保目录存在，如果已存在则返回现有目录ID"""
        existing_dirs = self.list_directory(parent_id)
        for d in existing_dirs:
            if d["name"] == dir_name:
                return d["id"]
        
        return self.create_directory(parent_id, dir_name)
    
    def offline_download(self, url, parent_id, filename, retry_count=0):
        """提交离线下载任务"""
        headers = self.token_manager.get_auth_header()
        payload = {
            "url": url,
            "dirID": parent_id,
            "fileName": filename
        }
        
        for attempt in range(retry_count + 1):
            try:
                download_url = f"{OPEN_API_HOST}{API_PATHS['OFFLINE_DOWNLOAD']}"
                response = self._call_api("POST", download_url, json=payload, headers=headers)
                if not response or response.status_code != 200:
                    continue
                
                data = response.json()
                if data.get("code") == 0:
                    return data["data"]["taskID"]
            except Exception as e:
                logger.error(f"提交离线下载任务失败: {e}")
            time.sleep(1)
        return None
    
    def get_offline_task_progress(self, task_id):
        """获取离线下载任务进度"""
        headers = self.token_manager.get_auth_header()
        params = {"taskID": task_id}
        
        try:
            progress_url = f"{OPEN_API_HOST}{API_PATHS['DOWNLOAD_PROGRESS']}"
            response = self._call_api("GET", progress_url, params=params, headers=headers)
            if not response or response.status_code != 200:
                return 0, -1, "查询失败"
            
            data = response.json()
            if data.get("code") == 0:
                progress_data = data["data"]
                progress = progress_data.get("process", 0)
                status = progress_data.get("status", -1)
                status_text = TASK_STATUS_MAP.get(status, "未知状态")
                return progress, status, status_text
            else:
                return 0, -1, "查询失败"
        except Exception as e:
            logger.error(f"获取离线任务进度失败: {e}")
            return 0, -1, "查询异常"

class FastLinkProcessor:
    @staticmethod
    def parse_share_link(share_link):
        """解析秒传链接"""
        common_base_path = ""
        is_common_path_format = False
        is_v2_etag_format = False
        
        # 使用前缀映射简化处理
        prefix_map = {
            COMMON_PATH_LINK_PREFIX_V2: (True, True),
            COMMON_PATH_LINK_PREFIX_V1: (True, False),
            LEGACY_FOLDER_LINK_PREFIX_V2: (False, True),
            LEGACY_FOLDER_LINK_PREFIX_V1: (False, False)
        }
        
        for prefix, (is_common, is_v2) in prefix_map.items():
            if share_link.startswith(prefix):
                share_link = share_link[len(prefix):]
                is_common_path_format = is_common
                is_v2_etag_format = is_v2
                break
        
        if is_common_path_format:
            delimiter_pos = share_link.find(COMMON_PATH_DELIMITER)
            if delimiter_pos > -1:
                common_base_path = share_link[:delimiter_pos]
                share_link = share_link[delimiter_pos + 1:]
        
        files = []
        for s_link in share_link.split('$'):
            if not s_link:
                continue
            parts = s_link.split('#')
            if len(parts) < 3:
                continue
            
            etag = parts[0]
            size = parts[1]
            file_path = '#'.join(parts[2:])
            
            if is_common_path_format and common_base_path:
                file_path = common_base_path + file_path
            
            files.append({
                "etag": etag,
                "size": int(size),
                "file_name": file_path,
                "is_v2_etag": is_v2_etag_format
            })
        
        return files
    
    @staticmethod
    def optimized_etag_to_hex(optimized_etag, is_v2_etag):
        """将优化后的ETag转换为十六进制格式"""
        if not is_v2_etag:
            return optimized_etag
        
        try:
            # 如果已经是十六进制格式，直接返回
            if len(optimized_etag) == 32 and all(c in '0123456789abcdefABCDEF' for c in optimized_etag):
                return optimized_etag.lower()
            
            num = 0
            for char in optimized_etag:
                if char not in BASE62_CHARS:
                    return optimized_etag
                num = num * 62 + BASE62_CHARS.index(char)
            
            hex_str = hex(num)[2:].lower()
            # 处理长度
            if len(hex_str) > 32:
                hex_str = hex_str[-32:]
            elif len(hex_str) < 32:
                hex_str = hex_str.zfill(32)
            
            return hex_str
        except Exception as e:
            logger.error(f"ETag转换失败: {e}")
            return optimized_etag
        

# ====================== 115网盘工具类 ======================
class ShareTransferTool:
    """115分享链接转存工具"""
    
    def __init__(self, cookies: str):
        self.cookies = cookies
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        
        try:
            from p115 import P115ShareFileSystem
            from p115client import P115Client
            from p115client.tool.util import share_extract_payload
            
            logger.info("🛠️ 正在初始化115客户端...")
            self.client = P115Client(cookies)
            logger.info("✅ 115客户端初始化成功")
        except ImportError:
            logger.error("❌ 缺少p115client库，无法使用115功能")
            raise
        except Exception as e:
            logger.error(f"❌ 115客户端初始化失败: {str(e)}")
            raise
    
    def get_target_directory_id(self, target_path: str) -> int:
        """获取目标目录ID，如果不存在则创建"""
        root_id = 0
        path_parts = [part for part in target_path.split("/") if part]
        current_id = root_id
        
        for part in path_parts:
            found = False
            offset = 0
            limit = 1000
            
            while True:
                resp = self.client.fs_files({"cid": current_id, "offset": offset, "limit": limit})
                
                if not resp["state"]:
                    raise Exception(f"获取目录列表失败: {resp.get('error', '未知错误')}")
                
                data_list = resp["data"]
                count = len(data_list)
                
                for item in data_list:
                    if item.get("n") == part and "cid" in item:
                        current_id = int(item["cid"])
                        found = True
                        break
                
                if found:
                    break
                
                total_count = resp.get("count", count)
                if (offset + count) >= total_count:
                    break
                
                offset += count
            
            if not found:
                resp = self.client.fs_mkdir({"pid": current_id, "cname": part})
                
                if resp["state"]:
                    current_id = int(resp["cid"])
                else:
                    error_msg = resp.get("error", "未知错误")
                    if "已存在" in error_msg or "重名" in error_msg:
                        resp = self.client.fs_files({"cid": current_id, "offset": 0, "limit": 1000})
                        if resp["state"]:
                            for item in resp["data"]:
                                if item.get("n") == part and "cid" in item:
                                    current_id = int(item["cid"])
                                    found = True
                                    break
                        if not found:
                            raise Exception(f"创建目录失败: {part} - {error_msg}")
                    else:
                        raise Exception(f"创建目录失败: {part} - {error_msg}")
        
        return current_id
    
    def transfer_share(self, share_url: str, receive_code: Optional[str], target_path: str) -> int:
        """转存分享内容到指定目录，返回目标目录ID"""
        from p115client.tool.util import share_extract_payload
        from p115 import P115ShareFileSystem
        
        data = share_extract_payload(share_url)
        
        share_code = data["share_code"]
        if not receive_code:
            receive_code = data.get("receive_code", "")
        
        # 获取目标目录ID
        target_dir_id = self.get_target_directory_id(target_path)
        
        # 创建分享文件系统实例
        share_fs = P115ShareFileSystem(
            client=self.client, 
            share_code=share_code, 
            receive_code=receive_code
        )
        
        # 发送转存请求
        resp = share_fs.receive(0, target_dir_id)
        
        if resp["state"]:
            logger.info("✅ 转存成功！")
            return target_dir_id
        else:
            error_msg = resp.get("error", "未知错误")
            raise Exception(f"转存失败: {error_msg}")

class PanTransfer:
    """115网盘到123云盘迁移工具"""
    
    def __init__(self, pan_client: Pan123Client, cookies: str):
        self.pan_client = pan_client
        
        # 初始化115客户端
        try:
            from p115client import P115Client
            from p115client.tool.iterdir import iterdir
            
            logger.info("正在初始化115网盘客户端...")
            self.client_115 = P115Client(cookies=cookies)
            logger.info("115网盘登录成功")
        except ImportError:
            logger.error("❌ 缺少p115client库，无法使用115功能")
            raise
        except Exception as e:
            logger.error(f"115网盘登录验证失败: {str(e)}")
            raise
    
    def get_115_directory_id_by_path(self, path: str) -> int:
        """根据路径获取115网盘目录ID"""
        current_id = 0
        path_parts = [part for part in path.split("/") if part]
        
        for part in path_parts:
            found = False
            offset = 0
            limit = 1000
            
            while True:
                resp = self.client_115.fs_files({"cid": current_id, "offset": offset, "limit": limit})
                
                if not resp["state"]:
                    raise Exception(f"获取目录列表失败: {resp.get('error', '未知错误')}")
                
                data_list = resp["data"]
                count = len(data_list)
                
                for item in data_list:
                    if item.get("n") == part and "cid" in item:
                        current_id = int(item["cid"])
                        found = True
                        break
                
                if found:
                    break
                
                total_count = resp.get("count", count)
                if (offset + count) >= total_count:
                    break
                
                offset += count
            
            if not found:
                raise Exception(f"在115网盘中找不到目录: {part}")
        
        return current_id
    
    def filter_allowed_files(self, file_list: list) -> tuple:
        """过滤掉不允许的文件类型"""
        allowed_files = []
        filtered_files = []
        
        for file_info in file_list:
            _, ext = os.path.splitext(file_info["name"].lower())
            if ext in ALLOWED_EXTENSIONS:
                allowed_files.append(file_info)
            else:
                filtered_files.append(file_info)
        
        return allowed_files, filtered_files
    
    def get_115_structure(self, dir_id: int) -> tuple:
        """获取115网盘指定目录下的完整结构"""
        dir_list = []
        file_list = []
        
        try:
            from p115client.tool.iterdir import iterdir
            
            queue = deque([dir_id])
            visited = set([dir_id])
            
            while queue:
                current_dir_id = queue.popleft()
                
                for item in iterdir(
                    client=self.client_115,
                    cid=current_dir_id,
                    recursive=False,
                    include_dir=True
                ):
                    if item.get("is_dir", False) or item.get("is_directory", False):
                        dir_info = {
                            "id": item["id"],
                            "parent_id": current_dir_id,
                            "name": item["name"]
                        }
                        dir_list.append(dir_info)
                        
                        if item["id"] not in visited:
                            visited.add(item["id"])
                            queue.append(item["id"])
                    else:
                        file_info = {
                            "name": item["name"],
                            "pickcode": item["pickcode"],
                            "size": item["size"],
                            "parent_id": current_dir_id
                        }
                        file_list.append(file_info)
                
                time.sleep(0.2)
        
        except Exception as e:
            logger.error(f"获取目录结构失败: {str(e)}")
        
        return dir_list, file_list
    
    def transfer_files(self, source_dir_id: int, target_dir_id_123: int) -> dict:
        """从115网盘迁移文件到123云盘，返回统计信息"""
        start_time = time.time()
        stats = {
            "start_time": start_time,
            "end_time": None,
            "total_files": 0,
            "filtered_files": 0,
            "submitted_files": 0,
            "success_files": 0,
            "failed_files": 0,
            "total_size": 0,
            "filtered_size": 0,
            "submitted_size": 0
        }
        
        # 建立目录映射
        dir_mapping = {source_dir_id: target_dir_id_123}
        
        # 获取115文件信息
        dir_list, file_list = self.get_115_structure(source_dir_id)
        
        if not dir_list and not file_list:
            logger.warning("没有找到可迁移的文件或目录")
            return stats
        
        # 构建目录树结构
        dir_tree = defaultdict(list)
        for dir_info in dir_list:
            dir_tree[dir_info["parent_id"]].append(dir_info)
        
        # 使用BFS创建目录结构
        queue = deque(dir_tree.get(source_dir_id, []))
        created_dirs = 0
        
        logger.info("开始在123云盘上创建目录结构...")
        while queue:
            dir_info = queue.popleft()
            parent_115_id = dir_info["parent_id"]
            dir_name = dir_info["name"]
            
            parent_123_id = dir_mapping.get(parent_115_id)
            if parent_123_id is None:
                continue
            
            new_dir_id = self.pan_client.ensure_directory(parent_123_id, dir_name)
            if new_dir_id:
                dir_mapping[dir_info["id"]] = new_dir_id
                created_dirs += 1
                
                if dir_info["id"] in dir_tree:
                    queue.extend(dir_tree[dir_info["id"]])
            
            time.sleep(0.2)
        
        logger.info(f"目录创建完成! 成功创建 {created_dirs} 个目录")
        
        # 文件过滤
        allowed_files, filtered_files = self.filter_allowed_files(file_list)
        stats["total_files"] = len(file_list)
        stats["filtered_files"] = len(filtered_files)
        stats["total_size"] = sum(f["size"] for f in file_list)
        stats["filtered_size"] = sum(f["size"] for f in filtered_files)
        
        # 迁移文件
        submitted_files = allowed_files
        stats["submitted_files"] = len(submitted_files)
        stats["submitted_size"] = sum(f["size"] for f in submitted_files)
        
        logger.info(f"开始迁移 {len(submitted_files)} 个文件到123云盘 (总大小: {self.format_size(stats['submitted_size'])})...")
        
        success_count = 0
        failed_files = []
        task_list = []
        
        for i, file_info in enumerate(submitted_files, 1):
            file_name = file_info["name"]
            target_dir_id = dir_mapping.get(file_info["parent_id"], target_dir_id_123)
            direct_link = f"{CUSTOM_DIRECT_LINK_SERVICE}{file_info['pickcode']}"
            
            task_id = self.pan_client.offline_download(direct_link, target_dir_id, file_name, retry_count=2)
            if task_id:
                success_count += 1
                task_list.append({
                    "task_id": task_id,
                    "file_name": file_name
                })
            else:
                failed_files.append(file_info)
            
            # 每10个文件显示一次进度
            if i % 10 == 0 or i == len(submitted_files):
                logger.info(f"已提交: {i}/{len(submitted_files)}")
            
            time.sleep(0.5)
        
        # 最终统计
        end_time = time.time()
        stats["end_time"] = end_time
        stats["success_files"] = success_count
        stats["failed_files"] = len(failed_files)
        
        elapsed_time = end_time - start_time
        hours, rem = divmod(elapsed_time, 3600)
        minutes, seconds = divmod(rem, 60)
        time_str = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
        
        logger.info(f"迁移完成! 成功提交 {success_count}/{len(submitted_files)} 个文件")
        logger.info(f"总耗时: {time_str}")
        
        return stats
    
    def delete_115_directory(self, dir_id: int):
        """删除115网盘目录（移动到回收站）"""
        try:
            resp = self.client_115.fs_delete([dir_id])
            if not resp["state"]:
                logger.error(f"删除失败: {resp.get('error', '未知错误')}")
        except Exception as e:
            logger.error(f"删除目录时出错: {str(e)}")
    
    @staticmethod
    def format_size(size_bytes: int) -> str:
        """格式化文件大小"""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"


class TelegramBotHandler:
    def __init__(self, token, pan_client, allowed_user_ids):
        self.token = token
        self.pan_client = pan_client
        self.allowed_user_ids = allowed_user_ids
        self.updater = Updater(token, use_context=True)
        self.dispatcher = self.updater.dispatcher
        self.start_time = pan_client.token_manager.start_time
        self.active_tasks = {}

        # 初始化115工具
        self.share_transfer = None
        if COOKIES_115:
            try:
                self.share_transfer = ShareTransferTool(COOKIES_115)
            except Exception as e:
                logger.error(f"115工具初始化失败: {e}")
        
        # 注册处理程序
        self.dispatcher.add_handler(CommandHandler("start", self.start_command))
        self.dispatcher.add_handler(CommandHandler("export", self.export_command))
        self.dispatcher.add_handler(CommandHandler("sync_full", self.sync_full_command))
        self.dispatcher.add_handler(CommandHandler("clear_trash", self.clear_trash_command))
        self.dispatcher.add_handler(CommandHandler("add", self.add_command))
        self.dispatcher.add_handler(CommandHandler("delete", self.delete_command))
        self.dispatcher.add_handler(CommandHandler("info", self.info_command))
        self.dispatcher.add_handler(CommandHandler("refresh_token", self.refresh_token_command))
        self.dispatcher.add_handler(CommandHandler("migrate", self.migrate_command))
        self.dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, self.handle_text))
        self.dispatcher.add_handler(MessageHandler(Filters.document, self.handle_document))
        self.dispatcher.add_handler(CallbackQueryHandler(self.button_callback))
        
        # 设置菜单命令
        self.set_menu_commands()
    
    def set_menu_commands(self):
        """设置Telegram Bot菜单命令"""
        commands = [
            BotCommand("start", "个人信息"),
            BotCommand("export", "导出JSON"),
            BotCommand("sync_full", "全量同步"),
            BotCommand("info", "用户信息"),
            BotCommand("add", "添加用户"),
            BotCommand("delete", "删除用户"),
            BotCommand("migrate", "115搬运"),            
            BotCommand("clear_trash", "清空回收站"),
            BotCommand("refresh_token", "刷新Token"),
        ]
        
        try:
            self.updater.bot.set_my_commands(commands)
        except Exception as e:
            logger.error(f"设置菜单命令失败: {e}")
    
    def start(self):
        """启动机器人"""
        try:
            # 启动轮询并清除历史消息
            self.updater.start_polling(drop_pending_updates=True)
            logger.info("🤖 机器人已启动，等待消息...")
            self.updater.idle()
        except Exception as e:
            logger.error(f"启动机器人失败: {e}")
    
    # 管理员权限检查装饰器
    def admin_required(func):
        @wraps(func)
        def wrapper(self, update: Update, context: CallbackContext, *args, **kwargs):
            user_id = update.message.from_user.id
            if user_id not in self.allowed_user_ids:
                return
            return func(self, update, context, *args, **kwargs)
        return wrapper
    
    def auto_delete_message(self, context, chat_id, message_id, delay=3):
        """自动删除消息（支持群聊和私聊）"""
        def delete():
            try:
                context.bot.delete_message(chat_id=chat_id, message_id=message_id)
            except Exception:
                pass
        threading.Timer(delay, delete).start()
    
    def send_auto_delete_message(self, update, context, text, delay=3, chat_id=None, parse_mode=None):
        """发送自动删除的消息"""
        if chat_id is None:
            if update and update.message:
                chat_id = update.message.chat_id
            elif update and update.callback_query and update.callback_query.message:
                chat_id = update.callback_query.message.chat_id
            elif context and hasattr(context, '_chat_id'):
                chat_id = context._chat_id
            else:
                return None
        
        message = context.bot.send_message(chat_id=chat_id, text=text, parse_mode=parse_mode)
        self.auto_delete_message(context, chat_id, message.message_id, delay)
        return message  # 返回消息对象
    
    @admin_required
    def start_command(self, update: Update, context: CallbackContext):
        """处理/start命令 - 优化版用户信息输出"""
        try:
            user_info = self.pan_client.get_user_info()
            if not user_info:
                self.send_auto_delete_message(update, context, "❌ 无法获取用户信息")
                return
            
            # 计算运行时间
            uptime = datetime.now() - self.start_time
            days = uptime.days
            hours, remainder = divmod(uptime.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            
            # 格式化手机号码和UID
            phone = user_info.get("passport", "")
            if phone and len(phone) > 7:
                phone = phone[:3] + "*" * 4 + phone[-4:]
            
            uid = str(user_info.get("uid", ""))
            if uid and len(uid) > 6:
                uid = uid[:3] + "*" * (len(uid) - 6) + uid[-3:]
            
            # 格式化存储空间
            space_permanent = format_size(user_info.get("spacePermanent", 0))
            space_used = format_size(user_info.get("spaceUsed", 0))
            direct_traffic = format_size(user_info.get("directTraffic", 0))
            
            # 计算存储空间使用率
            if user_info.get("spacePermanent", 0) > 0:
                usage_percent = (user_info.get("spaceUsed", 0) / user_info.get("spacePermanent", 1)) * 100
                usage_bar = generate_usage_bar(usage_percent)
            else:
                usage_percent = 0
                usage_bar = ""
            
            # 构建用户信息消息
            message = (
                f"🚀 <b>123云盘用户信息</b> | {'👑 <b>尊享账户</b>' if user_info.get('vip', False) else '🔒 <b>普通账户</b>'}\n"
                f"══════════════════════\n"
                f"👤 <b>昵称:</b> {user_info.get('nickname', '未知')}\n"
                f"🆔 <b>账户ID:</b> {uid}\n"
                f"📱 <b>手机号码:</b> {phone}\n\n"
                f"💾 <b>存储空间</b> ({usage_percent:.1f}%)\n"
                f"├ 永久: {space_permanent}\n"
                f"├ 已用: {space_used}\n"
                f"└ {usage_bar}\n\n"
                f"📡 <b>流量信息</b>\n"
                f"└ 直链: {direct_traffic}\n"
                f"══════════════════════\n\n"
                f"⚙️ <b>当前配置:</b>\n"
                f"├ 保存目录: <code>{DEFAULT_SAVE_DIR or '根目录'}</code>\n"
                f"├ 导出目录: <code>{', '.join(EXPORT_BASE_DIRS) if EXPORT_BASE_DIRS else '根目录'}</code>\n"
                f"├ 搜索深度: <code>{SEARCH_MAX_DEPTH}层</code>\n"
                f"└ 数据缓存: <code>{len(self.pan_client.directory_cache)}</code>\n\n"
                f"🤖 <b>机器人控制中心</b>\n"
                f"▫️ /export - 导出文件\n"
                f"▫️ /sync_full - 全量同步\n"
                f"▫️ /info - 查询用户信息\n"
                f"▫️ /add - 添加用户\n"    
                f"▫️ /delete - 删除用户\n"                                             
                f"▫️ /clear_trash - 清空回收站\n"
                f"▫️ /migrate - 115搬运\n\n"
                f"📦 <b>Version:</b> <code>{VERSION}</code>\n"
                f"⏱️ <b>已运行:</b> {days}天{hours}小时{minutes}分{seconds}秒"
            )

            update.message.reply_text(
                message, 
                parse_mode="HTML",
                disable_web_page_preview=True
            )
        except Exception as e:
            logger.error(f"处理/start命令出错: {e}")
            self.send_auto_delete_message(update, context, "❌ 获取用户信息失败")

    def search_database_by_name(self, name_pattern):
        """在数据库中进行模糊搜索"""
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("SELECT * FROM directory_cache WHERE filename LIKE ? ORDER BY filename", (f'%{name_pattern}%',))
                rows = c.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"数据库搜索失败: {e}")
            return []
    
    def get_user_privilege(self, user_id):
        """获取用户权限信息"""
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("SELECT * FROM user_privileges WHERE user_id = ?", (user_id,))
                row = c.fetchone()
                if row:
                    return dict(row)
        except Exception as e:
            logger.error(f"查询用户权限失败: {e}")
        return None
    
    def update_user_export_count(self, user_id, folder_count):
        """更新用户导出次数"""
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                today = datetime.now().strftime("%Y-%m-%d")
                
                # 获取当前用户信息
                user_info = self.get_user_privilege(user_id)
                if user_info:
                    # 检查是否需要重置
                    last_export_date = user_info.get("last_export_date")
                    if last_export_date and last_export_date != today:
                        # 重置次数
                        c.execute("UPDATE user_privileges SET export_count = 0, last_export_date = ? WHERE user_id = ?", 
                                  (today, user_id))
                    
                    # 增加导出次数
                    c.execute("UPDATE user_privileges SET export_count = export_count + ?, last_export_date = ? WHERE user_id = ?", 
                              (folder_count, today, user_id))
                else:
                    # 新用户
                    c.execute("INSERT INTO user_privileges (user_id, privilege_level, export_count, last_export_date) VALUES (?, ?, ?, ?)",
                              (user_id, "user", folder_count, today))
                
                # 记录导出历史
                c.execute("INSERT INTO export_history (user_id, folder_count) VALUES (?, ?)",
                          (user_id, folder_count))
                
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"更新用户导出次数失败: {e}")
            return False

    def export_command(self, update: Update, context: CallbackContext):
        """处理/export命令"""
        user_id = update.message.from_user.id
        search_query = " ".join(context.args) if context.args else ""
        chat_type = update.message.chat.type
        in_group = chat_type in ['group', 'supergroup']

        # 如果是群聊，先删除用户消息
        if in_group:
            try:
                update.message.delete()
            except Exception:
                pass

        if not search_query:
            self.send_auto_delete_message(update, context, "❌ 请指定文件夹名称！格式: /export <文件夹名称>")
            return
         
        # 检查用户权限
        user_info = self.get_user_privilege(user_id)
        is_admin = user_id in self.allowed_user_ids
        is_svip = user_info and user_info.get("privilege_level") == "svip"  # 新增SVIP检查

        # 非管理员且非SVIP用户检查权限
        if not is_admin and not is_svip:  # 修改检查条件
            if not user_info:
                self.send_auto_delete_message(update, context, "❌ 您没有使用导出功能的权限，请联系管理员")
                return
            if search_query.lower() in BANNED_EXPORT_NAMES:
                self.send_auto_delete_message(update, context, f"❌ 禁止导出名称为 '{search_query}' 的文件夹")
                return
     
            # 检查是否超过限制
            today = datetime.now().strftime("%Y-%m-%d")
            last_export_date = user_info.get("last_export_date", "")
            export_count = user_info.get("export_count", 0)
            
            # 如果是新的一天，重置次数
            if last_export_date != today:
                export_count = 0
            
            if export_count >= DAILY_EXPORT_LIMIT:
                self.send_auto_delete_message(update, context, f"❌ 您今日的导出次数已达上限（{DAILY_EXPORT_LIMIT}次），请明天再试或联系管理员升级权限")
                return
        
        if in_group:
            # 发送提示消息并保存消息ID以便撤回
            msg = self.send_auto_delete_message(
              update, context,
              f"🔍 正在搜索文件夹: '{search_query}'...\n结果将通过私聊发送给您",
              delay=5
            )
            context.user_data['group_temp_msg_id'] = msg.message_id
            context.user_data['group_chat_id'] = update.message.chat_id  # 保存群聊ID
        else:
            self.send_auto_delete_message(update, context, f"🔍 正在搜索文件夹: '{search_query}'...")

        try:
            results = self.search_database_by_name(search_query)
            if not results:
                self.send_auto_delete_message(update, context, f"❌ 未找到包含 '{search_query}' 的文件夹")
                return
            
            context.user_data['export_search_results'] = results
            context.user_data['export_selected_indices'] = set()
            
            keyboard = []
            max_buttons = 40
            for i, result in enumerate(results[:max_buttons]):
                filename = result["filename"]
                display_name = filename if len(filename) <= 50 else f"{filename[:47]}..."
                keyboard.append([
                    InlineKeyboardButton(f"{i+1}. {display_name}", callback_data=f"export_toggle_{i}")
                ])
            
            action_buttons = [
                InlineKeyboardButton("✅ 全选", callback_data="export_select_all"),
                InlineKeyboardButton("🔄 反选", callback_data="export_deselect_all"),
                InlineKeyboardButton("🚀 导出", callback_data="export_confirm"),
                InlineKeyboardButton("❌ 退出", callback_data="export_cancel")
            ]
            
            keyboard.append(action_buttons[:2])
            keyboard.append(action_buttons[2:])
            reply_markup = InlineKeyboardMarkup(keyboard)

            if in_group:
                message = context.bot.send_message(
                    chat_id=update.message.chat_id,
                    text=f"✅ 找到 {len(results)} 个匹配项\n请选择要导出的文件夹:",
                    reply_markup=reply_markup
                )
            else:
                message = update.message.reply_text(
                    f"✅ 找到 {len(results)} 个匹配项\n请选择要导出的文件夹:",
                    reply_markup=reply_markup
                )
            
            context.user_data['export_message_id'] = message.message_id
            
            job_context = {
                "chat_id": update.message.chat_id,
                "user_data": context.user_data
            }
            context.job_queue.run_once(
                self.export_timeout, 
                60, 
                context=job_context,
                name=f"export_timeout_{message.message_id}"
            )
        except Exception as e:
            logger.error(f"搜索文件夹失败: {e}")
            self.send_auto_delete_message(update, context, f"❌ 搜索失败: {e}")

    def export_choice_callback(self, update: Update, context: CallbackContext):
        """处理导出选择的回调"""
        query = update.callback_query
        query.answer()
        data = query.data
        
        results = context.user_data.get('export_search_results', [])
        selected_indices = context.user_data.get('export_selected_indices', set())
        
        if not results:
            query.edit_message_text("❌ 选择超时，请重新搜索")
            return
        
        if data.startswith("export_toggle_"):
            try:
                index = int(data.split("_")[2])
                if index in selected_indices:
                    selected_indices.remove(index)
                else:
                    selected_indices.add(index)
            except (ValueError, IndexError):
                pass
        elif data == "export_select_all":
            selected_indices = set(range(len(results)))
        elif data == "export_deselect_all":
            selected_indices = set()
        elif data == "export_confirm":
            self.process_export_selection(update, context, selected_indices)
            return
        elif data == "export_cancel":
            query.edit_message_text("❌ 导出操作已取消")
            self.cleanup_export_context(context.user_data)
            return
        
        context.user_data['export_selected_indices'] = selected_indices
        self.update_export_message(update, context, results, selected_indices)
    
    def update_export_message(self, update: Update, context: CallbackContext, results, selected_indices):
        """更新导出选择消息"""
        query = update.callback_query
        selected_count = len(selected_indices)
        
        keyboard = []
        max_buttons = 40
        for i, result in enumerate(results[:max_buttons]):
            filename = result["filename"]
            display_name = filename if len(filename) <= 50 else f"{filename[:47]}..."
            prefix = "✅ " if i in selected_indices else "⬜ "
            keyboard.append([
                InlineKeyboardButton(f"{prefix}{i+1}. {display_name}", callback_data=f"export_toggle_{i}")
            ])
        
        action_buttons = [
            InlineKeyboardButton("✅ 全选", callback_data="export_select_all"),
            InlineKeyboardButton("🔄 反选", callback_data="export_deselect_all"),
            InlineKeyboardButton(f"🚀 导出({selected_count})", callback_data="export_confirm"),
            InlineKeyboardButton("❌ 取消", callback_data="export_cancel")
        ]
        
        keyboard.append(action_buttons[:2])
        keyboard.append(action_buttons[2:])
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        query.edit_message_text(
            text=f"✅ 找到 {len(results)} 个匹配项\n已选择 {selected_count} 个文件夹:",
            reply_markup=reply_markup
        )
    
    def export_timeout(self, context: CallbackContext):
        """导出选择超时处理"""
        job = context.job
        if not job or not job.context:
            return
        
        job_context = job.context
        chat_id = job_context.get("chat_id")
        user_data = job_context.get("user_data", {})

        if not chat_id:
            return
        
        if 'export_message_id' in user_data:
            message_id = user_data['export_message_id']
            try:
                self.updater.bot.edit_message_text(chat_id=chat_id, message_id=message_id, text="⏱️ 操作超时，导出已自动取消")
            except Exception:
                pass
        
        self.cleanup_export_context(user_data)
    
    def cleanup_export_context(self, user_data: dict):
        """清理导出相关的上下文数据"""
        keys_to_remove = ['export_search_results', 'export_selected_indices', 'export_message_id', 'group_temp_msg_id']
        for key in keys_to_remove:
            if key in user_data:
                del user_data[key]
    
    def process_export_selection(self, update: Update, context: CallbackContext, selected_indices):
        """处理选择的导出任务"""
        query = update.callback_query
        results = context.user_data.get('export_search_results', [])
        if not results or not selected_indices:
            query.edit_message_text("❌ 请至少选择一个文件夹")
            return
            
        user_id = query.from_user.id
        folder_count = len(selected_indices)
        
        # 检查用户权限
        user_info = self.get_user_privilege(user_id)
        is_admin = user_id in self.allowed_user_ids
        is_svip = user_info and user_info.get("privilege_level") == "svip"  # 新增SVIP检查
        
        # 普通用户检查导出限制
        if not is_admin and not is_svip:  # 普通用户
            today = datetime.now().strftime("%Y-%m-%d")
            last_export_date = user_info.get("last_export_date", "")
            export_count = user_info.get("export_count", 0)
            
            # 如果是新的一天，重置次数
            if last_export_date != today:
                export_count = 0
            
            # 检查是否超过限制
            if export_count + folder_count > DAILY_EXPORT_LIMIT:
                query.edit_message_text(f"❌ 您今日的导出次数已达上限（{DAILY_EXPORT_LIMIT}次），已使用: {export_count}次，本次请求: {folder_count}次")
                return
            
        # 判断是否群聊环境
        in_group = 'group_temp_msg_id' in context.user_data

        # 发送临时消息
        if in_group:
            # 撤回之前的临时消息
            try:
                context.bot.delete_message(
                    chat_id=context.user_data['group_chat_id'],
                    message_id=context.user_data['group_temp_msg_id']
                )
            except Exception:
                pass
        
        # 发送新提示
        if in_group:
            query.edit_message_text(f"⏳ 开始导出 {folder_count} 个文件夹到私聊...")
            self.auto_delete_message(context, query.message.chat_id, query.message.message_id, 3)
        else:
            query.edit_message_text(f"⏳ 开始导出 {folder_count} 个文件夹...")
            self.auto_delete_message(context, query.message.chat_id, query.message.message_id, 3)
         
        if 'export_message_id' in context.user_data:
            message_id = context.user_data['export_message_id']
            job_name = f"export_timeout_{message_id}"
            for job in context.job_queue.get_jobs_by_name(job_name):
                job.schedule_removal()
        
        total = folder_count
        progress_messages = []
        
        for i, idx in enumerate(selected_indices):
            selected_folder = results[idx]
            folder_id = selected_folder["file_id"]
            folder_name = selected_folder["filename"]
            folder_path = selected_folder["full_path"]
            
            files = self.pan_client.get_directory_files(folder_id, folder_name)
            if not files:
                logger.warning(f"文件夹为空: {folder_name}")
                continue
                
            # 清理文件夹名称（移除非法字符）
            clean_folder_name = re.sub(r'[\\/*?:"<>|]', "", folder_name)
            # 在文件夹名称后添加斜杠
            common_path = f"{clean_folder_name}/"
            # 文件名保持原始格式（不带斜杠）
            file_name = f"{clean_folder_name}.json"
            
            # 每处理3个文件夹更新一次进度
            if i % 3 == 0:
                try:
                    msg = context.bot.send_message(
                        chat_id=query.message.chat_id,
                        text=f"⏳ 正在处理文件夹 [{i+1}/{total}]:\n├ 名称: {folder_name}\n└ 路径: {folder_path}"
                    )
                    progress_messages.append(msg.message_id)
                except Exception:
                    pass
            
            # 计算文件统计信息
            total_size = sum(file_info["size"] for file_info in files)
            file_count = len(files)
            
            json_data = {
                "usesBase62EtagsInExport": False,
                "commonPath": common_path,
                "totalFilesCount": file_count,
                "totalSize": total_size,
                "formattedTotalSize": format_size(total_size),
                "files": [
                    {"path": file_info["path"], "etag": file_info["etag"], "size": file_info["size"]}
                    for file_info in files
                ]
            }
            
            with open(file_name, "w", encoding="utf-8") as f:
                json.dump(json_data, f, ensure_ascii=False, indent=2)
            
            user_info = self.pan_client.get_user_info()
            nickname = user_info.get("nickname", "未知用户") if user_info else "未知用户"

            # 计算平均大小
            avg_size = total_size / file_count if file_count > 0 else 0
            
            caption = (             
                f"✨ 分享者：{nickname}\n"
                f"📁 文件名: {clean_folder_name}\n"
                f"📝 文件数: {file_count}\n"
                f"💾 总大小：{format_size(total_size)}\n"
                f"📊 平均大小：{format_size(avg_size)}\n\n"
                f"❤️ 123因您分享更完美！"
            )

            # 在发送文件处修改为私聊发送
            if in_group:
                # 通过私聊发送文件
                try:
                    with open(file_name, "rb") as f:
                        context.bot.send_document(
                            chat_id=user_id,  # 直接发送给用户ID（私聊）
                            document=f,
                            filename=file_name,
                            caption=caption
                        )
                except Exception as e:
                    logger.error(f"私聊发送失败: {e}")
                    # 在群聊中提示用户
                    context.bot.send_message(
                        chat_id=context.user_data['group_chat_id'],
                        text=f"❌ 无法发送私聊消息，请先私聊我 @{context.bot.username} 并点击'开始'"
                    )
            else:
                # 私聊环境正常发送
                with open(file_name, "rb") as f:
                    context.bot.send_document(
                    chat_id=query.message.chat_id,
                    document=f,
                    filename=file_name,
                    caption=caption
                )               
            
            os.remove(file_name)
        
        # 更新用户导出次数
        self.update_user_export_count(user_id, folder_count)
        
        # 导出完成后删除所有进度消息
        chat_id = query.message.chat_id
        for msg_id in progress_messages:
            try:
                context.bot.delete_message(chat_id=chat_id, message_id=msg_id)
            except Exception:
                pass
        
        self.cleanup_export_context(context.user_data)
 
    @admin_required
    def handle_document(self, update: Update, context: CallbackContext):
        """处理文档消息"""
        document = update.message.document
        file_name = document.file_name
        
        if document.mime_type != "application/json" and not file_name.endswith(".json"):
            self.send_auto_delete_message(update, context, "❌ 请发送JSON格式的文件！")
            return
        
        self.send_auto_delete_message(update, context, "📥 收到JSON文件，开始下载并解析...")
        
        file = context.bot.get_file(document.file_id)
        file_path = f"temp_{document.file_id}.json"
        file.download(file_path)
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                json_data = json.load(f)
            os.remove(file_path)
            self.process_json_file(update, context, json_data)
        except Exception as e:
            logger.error(f"处理JSON文件出错: {e}")
            self.send_auto_delete_message(update, context, f"❌ 处理JSON文件时出错: {e}")
    
    @admin_required
    def process_fast_link(self, update: Update, context: CallbackContext, share_link):
        """处理秒传链接转存"""
        try:
            files = FastLinkProcessor.parse_share_link(share_link)
            if not files:
                logger.warning("无法解析秒传链接或链接中无有效文件信息")
                self.send_auto_delete_message(update, context, "❌ 无法解析秒传链接")
                return
            
            self.send_auto_delete_message(update, context, f"✅ 解析成功！找到 {len(files)} 个文件，开始转存...")
            results, filtered_count, elapsed_time, original_total_count, original_total_size = self.transfer_files(update, context, files)
            self.send_transfer_results(update, context, results, filtered_count, elapsed_time, original_total_count, original_total_size)
        except Exception as e:
            logger.error(f"处理秒传链接出错: {e}")
            self.send_auto_delete_message(update, context, f"❌ 处理秒传链接时出错: {e}")
    
    @admin_required
    def process_json_file(self, update: Update, context: CallbackContext, json_data):
        """处理JSON文件转存"""
        try:
            if not isinstance(json_data, dict) or not json_data.get("files"):
                logger.warning("JSON格式无效，缺少files字段")
                self.send_auto_delete_message(update, context, "❌ JSON格式无效")
                return
            
            common_path = json_data.get("commonPath", "").strip()
            if common_path.endswith('/'):
                common_path = common_path[:-1]
            
            files = []
            for file_info in json_data["files"]:
                file_path = file_info.get("path", "")
                if common_path:
                    file_path = f"{common_path}/{file_path}"
                if not is_allowed_file(file_path):
                    continue
                files.append({
                    "etag": file_info.get("etag", ""),
                    "size": int(file_info.get("size", 0)),
                    "file_name": file_path,
                    "is_v2_etag": json_data.get("usesBase62EtagsInExport", False)
                })
            
            self.send_auto_delete_message(update, context, f"✅ 解析成功！找到 {len(files)} 个文件，开始转存...")
            results, filtered_count, elapsed_time, original_total_count, original_total_size = self.transfer_files(update, context, files)
            self.send_transfer_results(update, context, results, filtered_count, elapsed_time, original_total_count, original_total_size)
        except Exception as e:
            logger.error(f"处理JSON文件出错: {e}")
            self.send_auto_delete_message(update, context, f"❌ 处理JSON文件时出错: {e}")
    
    def transfer_files(self, update: Update, context: CallbackContext, files):
        """转存文件列表"""
        start_time = time.time()
        results = []
        original_total_count = len(files)
        original_total_size = sum(file_info["size"] for file_info in files)
        filtered_count = 0
        folder_cache = {}
        RATE_LIMIT = TRANSFER_RATE_LIMIT
        last_request_time = time.time()
        
        for i, file_info in enumerate(files):
            file_path = file_info["file_name"]
            file_size = file_info["size"]
            
            if not is_allowed_file(file_path):
                filtered_count += 1
                continue
                
            # 每处理10个文件显示一次进度
            if i % 10 == 0:
                self.send_auto_delete_message(
                    update, context, 
                    f"⏳ 正在处理文件 [{i+1}/{original_total_count}]\n文件名: {os.path.basename(file_path)}",
                    delay=5
                )
                
            elapsed = time.time() - last_request_time
            required_delay = max(0, 1.0/RATE_LIMIT - elapsed)
            if required_delay > 0:
                time.sleep(required_delay)
            
            try:
                path_parts = file_path.split('/')
                file_name = path_parts.pop()
                parent_id = self.pan_client.default_save_dir_id
                
                current_path = ""
                for part in path_parts:
                    if not part:
                        continue
                    current_path = f"{current_path}/{part}" if current_path else part
                    cache_key = f"{parent_id}/{current_path}"
                    
                    if cache_key in folder_cache:
                        parent_id = folder_cache[cache_key]
                        continue
                    
                    time.sleep(0.3)
                    folder = self.pan_client.create_folder(parent_id, part)
                    if folder:
                        folder_id = folder["FileId"]
                        folder_cache[cache_key] = folder_id
                        parent_id = folder_id
                
                etag = file_info["etag"]
                if file_info.get("is_v2_etag", False):
                    etag = FastLinkProcessor.optimized_etag_to_hex(etag, True)
                
                last_request_time = time.time()
                result = self.pan_client.rapid_upload(etag, file_size, file_name, parent_id)
                
                if result:
                    results.append({
                        "success": True,
                        "file_name": file_path,
                        "size": file_size,
                        "file_id": result["FileId"]
                    })
                else:
                    results.append({
                        "success": False,
                        "file_name": file_path,
                        "size": file_size,
                        "error": "秒传失败"
                    })
                    time.sleep(1.5)
            except (requests.exceptions.ConnectionError, ConnectionResetError) as e:
                results.append({
                    "success": False,
                    "file_name": file_path,
                    "size": file_size,
                    "error": f"网络错误: {e}"
                })
                time.sleep(3.0)
            except Exception as e:
                results.append({
                    "success": False,
                    "file_name": file_path,
                    "size": file_size,
                    "error": str(e)
                })
                time.sleep(2.0)
        
        elapsed_time = time.time() - start_time
        return results, filtered_count, elapsed_time, original_total_count, original_total_size
    
    def send_transfer_results(self, update: Update, context: CallbackContext, 
                             results, filtered_count, elapsed_time, 
                             original_total_count, original_total_size):
        """发送转存结果"""
        success_count = sum(1 for r in results if r["success"])
        failed_count = len(results) - success_count
        
        original_total_size_gb = original_total_size / (1024 ** 3)
        success_size = sum(r["size"] for r in results if r["success"])
        success_size_gb = success_size / (1024 ** 3)
        
        hours, remainder = divmod(elapsed_time, 3600)
        minutes, seconds = divmod(remainder, 60)
        time_str = f"{int(minutes)}分{int(seconds)}秒"
        if hours > 0:
            time_str = f"{int(hours)}小时{time_str}"
        
        result_text = (
            f"📊 转存完成！\n"
            f"├ 文件数量: {original_total_count}\n"
            f"├ 文件大小: {format_size(original_total_size)}\n"
            f"├ 成功数量: {success_count} (大小: {format_size(success_size)})\n"
            f"├ 失败数量: {failed_count}\n"
            f"├ 保存目录: {DEFAULT_SAVE_DIR or '根目录'}\n"
            f"└ 耗时: {time_str}\n"
        )
        
        if failed_count > 0:
            failed_files = []
            for result in results:
                if not result["success"]:
                    file_name = result["file_name"]
                    failed_files.append(f"• {file_name}: {result['error']}")
            failed_text = "\n".join(failed_files[:10])
            result_text += f"\n❌ 失败文件:\n{failed_text}"
            if failed_count > 10:
                result_text += f"\n...及其他 {failed_count - 10} 个失败文件"
        
        context.bot.send_message(chat_id=update.message.chat_id, text=result_text)
    
    @admin_required
    def sync_full_command(self, update: Update, context: CallbackContext):
        """处理/sync_full命令"""
        keyboard = [[
            InlineKeyboardButton("✅ 确认", callback_data='sync_full_confirm'),
            InlineKeyboardButton("❌ 取消", callback_data='sync_full_cancel')
        ]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        message = update.message.reply_text(
            "⚠️ 确认要执行全量同步吗？\n这将更新整个媒体库的目录缓存，可能需要较长时间。",
            reply_markup=reply_markup
        )
        context.user_data['confirmation_message_id'] = message.message_id

    def button_callback(self, update: Update, context: CallbackContext):
        """处理按钮回调"""
        query = update.callback_query
        query.answer()
        data = query.data
        
        if data.startswith("export_"):
            self.export_choice_callback(update, context)
        elif data.startswith("sync_full_"):
            chat_id = query.message.chat_id
            message_id = query.message.message_id
            try:
                context.bot.delete_message(chat_id=chat_id, message_id=message_id)
            except Exception:
                pass
            
            if data == 'sync_full_confirm':
                self.execute_full_sync(update, context)
            else:
                context.bot.send_message(chat_id=chat_id, text="❌ 全量同步已取消")

    def execute_full_sync(self, update: Update, context: CallbackContext):
        """执行全量同步"""
        chat_id = getattr(context, '_chat_id', None)
        self.send_auto_delete_message(update, context, "🔄 正在执行全量同步...", chat_id=chat_id)
        
        try:
            start_time = time.time()
            update_count = self.pan_client.full_sync_directory_cache()
            elapsed = time.time() - start_time
            self.send_auto_delete_message(
                update, context, 
                f"✅ 全量同步完成！\n├ 更新目录: {update_count} 个\n└ 耗时: {elapsed:.2f}秒",
                chat_id=chat_id
            )
        except Exception as e:
            logger.error(f"全量同步失败: {e}")
            self.send_auto_delete_message(update, context, "❌ 全量同步失败", chat_id=chat_id)
            
        if hasattr(context, '_chat_id'):
            del context._chat_id

    @admin_required
    def clear_trash_command(self, update: Update, context: CallbackContext):
        """处理/clear_trash命令"""
        self.send_auto_delete_message(update, context, "🔄 正在清空回收站...")
        try:
            if self.pan_client.clear_trash():
                self.send_auto_delete_message(update, context, "✅ 回收站已成功清空", delay=5)
            else:
                self.send_auto_delete_message(update, context, "❌ 清空回收站失败", delay=5)
        except Exception as e:
            logger.error(f"清空回收站出错: {e}")
            self.send_auto_delete_message(update, context, "❌ 清空回收站时出错", delay=5)

    @admin_required
    def process_share_link(self, update: Update, context: CallbackContext, share_url):
        """处理123云盘分享链接（保留目录结构）"""
        try:
            # 在后台线程中处理转存
            def do_share_transfer():
                try:
                    start_time = time.time()
                    success, failure, results, total_size = self.pan_client.save_share_files(
                        share_url, 
                        self.pan_client.default_save_dir_id
                    )
                    elapsed = time.time() - start_time
                    
                    # 构建结果消息
                    message = (
                        f"📦 分享链接转存完成！\n"
                        f"├ 成功: {success} 文件\n"
                        f"├ 失败: {failure} 文件\n"
                        f"├ 总大小: {format_size(total_size)}\n"
                        f"├ 保存到: {DEFAULT_SAVE_DIR}\n"
                        f"└ 耗时: {elapsed:.1f}秒"
                    )
                    
                    context.bot.send_message(
                        chat_id=update.message.chat_id, 
                        text=message
                    )
                    
                    # 如果有失败，发送失败详情
                    if failure > 0:
                        failed_list = "\n".join(
                            [f"• {r['file_name']}: {r.get('error', '未知错误')}" 
                             for r in results if not r['success']][:5]
                        )
                        if failure > 5:
                            failed_list += f"\n...及其他{failure-5}个文件"
                        
                        context.bot.send_message(
                            chat_id=update.message.chat_id,
                            text=f"❌ 失败文件:\n{failed_list}",
                            parse_mode="Markdown"
                        )
                    
                except Exception as e:
                    logger.error(f"处理分享链接出错: {e}")
                    self.send_auto_delete_message(
                        update, context, 
                        f"❌ 处理分享链接时出错: {e}",
                        chat_id=update.message.chat_id
                    )
            
            # 启动后台线程处理
            threading.Thread(target=do_share_transfer).start()
            self.send_auto_delete_message(
                update, context, 
                "⏳ 正在后台转存文件并保留目录结构，请稍候...\n完成后会通知结果",
                delay=5
            )
            
        except Exception as e:
            logger.error(f"处理分享链接出错: {e}")
            self.send_auto_delete_message(update, context, f"❌ 处理分享链接时出错: {e}")

    # ====================== 115转存功能 ======================
    @admin_required
    def extract_115_links(self, text: str) -> List[str]:
        """从文本中提取115分享链接（改进版）"""
        pattern = r'(https?://(?:115\.com|115cdn\.com)/s/[a-zA-Z0-9]+(?:\?password=[a-zA-Z0-9]+)?)'
        return re.findall(pattern, text)

    @admin_required
    def handle_text(self, update: Update, context: CallbackContext):
        """处理文本消息 - 仅保留秒传链接处理"""
        text = update.message.text.strip()
        
        # 秒传链接处理
        if (text.startswith(LEGACY_FOLDER_LINK_PREFIX_V1) or 
            text.startswith(LEGACY_FOLDER_LINK_PREFIX_V2) or 
            text.startswith(COMMON_PATH_LINK_PREFIX_V1) or 
            text.startswith(COMMON_PATH_LINK_PREFIX_V2) or
            ('#' in text and '$' in text)):
            self.send_auto_delete_message(update, context, "🔍 检测到秒传链接，开始解析...")
            self.process_fast_link(update, context, text)
        # 123云盘分享链接处理
        elif re.search(r'https?://(?:[a-zA-Z0-9-]+\.)*123[a-zA-Z0-9-]*\.[a-z]{2,6}/s/[a-zA-Z0-9\-_]+', text):
            self.send_auto_delete_message(update, context, "🔗 检测到123云盘分享链接，开始解析...")
            self.process_share_link(update, context, text)

        # 115分享链接处理
        share_links = self.extract_115_links(text)
        if share_links:
            for share_url in share_links:
                # 在后台线程中处理转存任务
                thread = threading.Thread(
                    target=self.process_115_share_link,
                    args=(update, context, share_url),
                    daemon=True
                )
                thread.start()
                self.active_tasks[share_url] = thread
                self.send_auto_delete_message(update, context, "🔗 检测到115分享链接，开始处理: {share_url}")
            return
        
    @admin_required
    def migrate_command(self, update: Update, context: CallbackContext):
        """处理/migrate命令"""
        user_id = update.effective_user.id
        chat_id = update.message.chat_id
        
        # 检查用户权限
        if user_id not in self.allowed_user_ids:
            self.send_auto_delete_message(update, context, "❌ 抱歉，您没有使用此命令的权限")
            return
        
        # 获取用户输入的自定义路径
        custom_path = " ".join(context.args).strip() if context.args else TARGET_PATH_115
        
        # 验证路径
        if not custom_path or len(custom_path) > 100:
            self.send_auto_delete_message(update, context, "❌ 路径无效：路径不能为空且长度不能超过100字符")
            return
        
        self.send_auto_delete_message(update, context, "🔄 收到迁移命令，目标路径: {custom_path}\n开始处理...")
        
        # 在后台线程中执行迁移
        thread = threading.Thread(
            target=self.process_manual_migration,
            args=(update, context, custom_path),
            daemon=True
        )
        thread.start()
        self.active_tasks[f"manual_migration_{custom_path}"] = thread
    
    def format_stats_message(self, stats: Dict) -> str:
        """格式化统计信息为消息"""
        elapsed = stats["end_time"] - stats["start_time"]
        hours, rem = divmod(elapsed, 3600)
        minutes, seconds = divmod(rem, 60)
        time_str = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
        
        message = (
            "📊 迁移统计报告\n"
            "══════════════════════\n"
            f"📂 扫描文件总数: {stats['total_files']}\n"
            f"🚫 过滤文件数: {stats['filtered_files']} (大小: {PanTransfer.format_size(stats['filtered_size'])})\n"
            f"📤 提交迁移文件数: {stats['submitted_files']} (大小: {PanTransfer.format_size(stats['submitted_size'])})\n"
            f"✅ 成功迁移文件数: {stats['success_files']}\n"
            f"❌ 迁移失败文件数: {stats['failed_files']}\n"
            f"⏱️ 总耗时: {time_str}\n"
            "══════════════════════"
        )
        
        return message
    
    def process_manual_migration(self, update: Update, context: CallbackContext, custom_path: str) -> None:
        """执行手动迁移流程"""
        bot = self.updater.bot
        chat_id = update.message.chat_id
        
        try:
            # 第一步：获取115目录ID
            msg = bot.send_message(
                chat_id=chat_id,
                text=f"🔍 第一步：获取115网盘目录ID...\n路径: {custom_path}"
            )
            self.auto_delete_message(context, chat_id, msg.message_id, 5)
        
            
            pan_transfer = PanTransfer(pan_client=self.pan_client, cookies=COOKIES_115)
            source_dir_id = pan_transfer.get_115_directory_id_by_path(custom_path)
            msg = bot.send_message(
                chat_id=chat_id,
                text=f"✅ 115网盘目录ID: {source_dir_id}\n"
                     f"路径: {custom_path}"
            )
            self.auto_delete_message(context, chat_id, msg.message_id, 5)
            
            # 第二步：获取123目标目录ID
            msg = bot.send_message(
                chat_id=chat_id,
                text="🔍 第二步：获取123云盘目录ID..."
            )
            self.auto_delete_message(context, chat_id, msg.message_id, 5)
            target_dir_id_123 = self.pan_client.get_or_create_directory(DEFAULT_SAVE_DIR)
            msg = bot.send_message(
                chat_id=chat_id,
                text=f"✅ 123云盘目录ID: {target_dir_id_123}\n"
                     f"路径: {DEFAULT_SAVE_DIR}"
            )
            self.auto_delete_message(context, chat_id, msg.message_id, 5)
            # 第三步：执行迁移
            msg = bot.send_message(
                chat_id=chat_id,
                text="🚀 第三步：开始迁移文件..."
            )
            self.auto_delete_message(context, chat_id, msg.message_id, 5)
            stats = pan_transfer.transfer_files(
                source_dir_id=source_dir_id,
                target_dir_id_123=target_dir_id_123
            )
            
            # 发送统计信息
            stats_message = self.format_stats_message(stats)
            bot.send_message(chat_id=chat_id, text=stats_message)
            
            # 第四步：清理源文件
            if DELETE_AFTER_TRANSFER and stats["failed_files"] == 0:
                msg = bot.send_message(
                    chat_id=chat_id,
                    text="🧹 清理115网盘源文件..."
                )
                self.auto_delete_message(context, chat_id, msg.message_id, 5)
                pan_transfer.delete_115_directory(source_dir_id)
                msg = bot.send_message(chat_id=chat_id, text="✅ 源文件已成功删除")
                self.auto_delete_message(context, chat_id, msg.message_id, 5)
            elif DELETE_AFTER_TRANSFER and stats["failed_files"] > 0:
                msg = bot.send_message(
                    chat_id=chat_id,
                    text=f"⚠️ 由于存在 {stats['failed_files']} 个迁移失败的文件，已跳过删除115源文件"
                )
                self.auto_delete_message(context, chat_id, msg.message_id, 5)
            else:
                msg = bot.send_message(
                    chat_id=chat_id,
                    text="ℹ️ 已跳过删除115源文件（配置选项）"
                )
                self.auto_delete_message(context, chat_id, msg.message_id, 5)
            
        except Exception as e:
            self.send_auto_delete_message(update, context, "❌ 手动迁移过程中出错: {str(e)}")
            traceback.print_exc()
        
        finally:
            # 清理任务
            task_key = f"manual_migration_{custom_path}"
            if task_key in self.active_tasks:
                del self.active_tasks[task_key]
    
    def process_115_share_link(self, update: Update, context: CallbackContext, share_url: str) -> None:
        """处理单个115分享链接的转存和迁移"""
        bot = self.updater.bot
        chat_id = update.message.chat_id
        
        try:
            if not self.share_transfer:
                self.send_auto_delete_message(update, context, "❌ 115功能未初始化，请检查配置")
                return
            
            # 第一步：转存分享链接到115网盘
            msg = bot.send_message(
                chat_id=chat_id,
                text=f"🔗 第一步：转存分享链接到115网盘...\n链接: {share_url}"
            )
            self.auto_delete_message(context, chat_id, msg.message_id, 5)
           
            target_dir_id = self.share_transfer.transfer_share(
                share_url=share_url,
                receive_code=None,
                target_path=TARGET_PATH_115
            )
            
            msg = bot.send_message(
                chat_id=chat_id,
                text=f"✅ 转存成功! 目标目录ID: {target_dir_id}\n"
                     f"⏳ 等待5秒确保转存完成..."
            )
            self.auto_delete_message(context, chat_id, msg.message_id, 5)
            time.sleep(5)
            
            # 第二步：迁移到123云盘
            msg = bot.send_message(
                chat_id=chat_id,
                text="🌐 第二步：迁移到123云盘..."
            )
            self.auto_delete_message(context, chat_id, msg.message_id, 5)
            
            pan_transfer = PanTransfer(pan_client=self.pan_client, cookies=COOKIES_115)
            # 获取或创建123目标目录
            target_dir_id_123 = self.pan_client.get_or_create_directory(DEFAULT_SAVE_DIR)
            msg = bot.send_message(
                chat_id=chat_id,
                text=f"✅ 123云盘目标目录ID: {target_dir_id_123}"
            )
            self.auto_delete_message(context, chat_id, msg.message_id, 5)
            
            stats = pan_transfer.transfer_files(
                source_dir_id=target_dir_id,
                target_dir_id_123=target_dir_id_123
            )
            
            # 发送统计信息
            stats_message = self.format_stats_message(stats)
            bot.send_message(chat_id=chat_id, text=stats_message)
            
            # 第三步：清理源文件
            if DELETE_AFTER_TRANSFER and stats["failed_files"] == 0:
                msg = bot.send_message(
                    chat_id=chat_id,
                    text="🧹 清理115网盘源文件..."
                )
                self.auto_delete_message(context, chat_id, msg.message_id, 5)
                pan_transfer.delete_115_directory(target_dir_id)
                msg = bot.send_message(
                    chat_id=chat_id,
                    text="✅ 源文件已成功删除"
                )
                self.auto_delete_message(context, chat_id, msg.message_id, 5)
            elif DELETE_AFTER_TRANSFER and stats["failed_files"] > 0:
                msg = bot.send_message(
                    chat_id=chat_id,
                    text=f"⚠️ 由于存在 {stats['failed_files']} 个迁移失败的文件，已跳过删除115源文件"
                )
                self.auto_delete_message(context, chat_id, msg.message_id, 5)
            else:
                msg = bot.send_message(
                    chat_id=chat_id,
                    text="ℹ️ 已跳过删除115源文件（配置选项）"
                )
                self.auto_delete_message(context, chat_id, msg.message_id, 5)
            
        except Exception as e:
            self.send_auto_delete_message(update, context, "❌ 手动迁移过程中出错: {str(e)}")
            traceback.print_exc()
        
        finally:
            # 清理任务
            if share_url in self.active_tasks:
                del self.active_tasks[share_url]
    # ====================== END 115转存功能 ======================
    
    @admin_required
    def add_command(self, update: Update, context: CallbackContext):
        """处理/add命令"""
        args = context.args
        reply_to = update.message.reply_to_message
        chat_id = update.message.chat_id
        message_id = update.message.message_id

        # 情况1：回复消息模式
        if reply_to:
            try:
                # 获取被回复用户的信息
                target_user = reply_to.from_user
                # 确定权限级别
                privilege_level = "user"
                if args and args[0].lower() == "svip":
                    privilege_level = "svip"
                # 添加用户到数据库
                with closing(sqlite3.connect(DB_PATH)) as conn:
                    c = conn.cursor()
                    c.execute('''INSERT OR REPLACE INTO user_privileges 
                              (user_id, privilege_level) 
                              VALUES (?, ?)''', 
                              (target_user.id, privilege_level))
                    conn.commit()

                # 构建响应消息
                name = target_user.first_name or target_user.username or str(target_user.id)
                response = (
                    f"✅ 已添加用户: {name}\n"
                    f"├ ID: `{target_user.id}`\n"
                    f"└ 权限: {privilege_level}"
                )
                # 发送回复消息并安排自动删除
                msg = update.message.reply_text(response, parse_mode="Markdown")
                self.auto_delete_message(context, chat_id, msg.message_id, 5)
                # 删除管理员发送的命令消息
                try:
                    context.bot.delete_message(chat_id=chat_id, message_id=message_id)
                except Exception as e:
                    logger.warning(f"无法删除命令消息: {e}")
                return
            except Exception as e:
                logger.error(f"通过回复添加用户失败: {e}")
                msg = update.message.reply_text(f"❌ 添加失败: {e}")
                self.auto_delete_message(context, chat_id, msg.message_id, 5)
                return
            
        # 情况2：传统参数模式
        if not args or len(args) < 1:
            usage = (
                "❌ 用法:\n"
                "1. 回复用户消息: `/add [svip]`\n"
                "2. 直接添加: `/add [svip] <用户ID>`"
            )
            msg = update.message.reply_text(usage, parse_mode="Markdown")
            self.auto_delete_message(context, chat_id, msg.message_id, 5)
            return
        
        try:
            # 检查是否指定了权限级别
            if args[0].lower() == "svip":
                if len(args) < 2:
                    update.message.reply_text("❌ 请提供用户ID")
                    self.auto_delete_message(context, chat_id, msg.message_id, 5)
                    return
                user_id = int(args[1])
                privilege_level = "svip"
            else:
                user_id = int(args[0])
                privilege_level = "user"
            
            # 添加用户到数据库
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                c.execute('''INSERT OR REPLACE INTO user_privileges 
                            (user_id, privilege_level) 
                            VALUES (?, ?)''', 
                          (user_id, privilege_level))
                conn.commit()
            response = (
                f"✅ 已添加用户\n"
                f"├ ID: `{user_id}`\n"
                f"└ 权限: {privilege_level}"
            )
            # 发送回复消息并安排自动删除
            msg = update.message.reply_text(response, parse_mode="Markdown")
            self.auto_delete_message(context, chat_id, msg.message_id, 5)
            # 删除管理员发送的命令消息
            try:
                context.bot.delete_message(chat_id=chat_id, message_id=message_id)
            except Exception as e:
                logger.warning(f"无法删除命令消息: {e}")
              
        except (ValueError, IndexError):
            msg = update.message.reply_text("❌ 无效的用户ID格式")
            self.auto_delete_message(context, chat_id, msg.message_id, 5)
        except Exception as e:
            logger.error(f"添加用户失败: {e}")
            msg = update.message.reply_text(f"❌ 添加失败: {e}")
            self.auto_delete_message(context, chat_id, msg.message_id, 5)
    
    @admin_required
    def delete_command(self, update: Update, context: CallbackContext):
        """处理/delete命令"""
        args = context.args
        reply_to = update.message.reply_to_message
        chat_id = update.message.chat_id
        message_id = update.message.message_id

        # 情况1：回复消息模式
        if reply_to:
            try:
                # 获取被回复用户的信息
                target_user = reply_to.from_user
                # 删除用户
                with closing(sqlite3.connect(DB_PATH)) as conn:
                    c = conn.cursor()
                    c.execute("DELETE FROM user_privileges WHERE user_id = ?", (target_user.id,))
                    conn.commit()
                    if c.rowcount > 0:
                        # 构建响应消息
                        name = target_user.first_name or target_user.username or str(target_user.id)
                        response = (
                            f"✅ 已删除用户: {name}\n"
                            f"└ ID: `{target_user.id}`"
                        )
                        # 发送回复消息并安排自动删除
                        msg = update.message.reply_text(response, parse_mode="Markdown")
                        self.auto_delete_message(context, chat_id, msg.message_id, 5)
                        # 删除管理员发送的命令消息
                        try:
                            context.bot.delete_message(chat_id=chat_id, message_id=message_id)
                        except Exception as e:
                            logger.warning(f"无法删除命令消息: {e}")
                    else:
                        msg = update.message.reply_text(f"❌ 用户不存在: {target_user.id}")
                        self.auto_delete_message(context, chat_id, msg.message_id, 5)
                return
            except Exception as e:
                logger.error(f"通过回复删除用户失败: {e}")
                msg = update.message.reply_text(f"❌ 删除失败: {e}")
                self.auto_delete_message(context, chat_id, msg.message_id, 5)
                return
            
        # 情况2：传统参数模式
        if not args or len(args) < 1:
            usage = (
                "❌ 用法:\n"
                "1. 回复用户消息: `/delete`\n"
                "2. 直接删除: `/delete <用户ID>`"
            )
            msg = update.message.reply_text(usage, parse_mode="Markdown")
            self.auto_delete_message(context, chat_id, msg.message_id, 5)
            return       
        try:
            user_id = int(args[0])
            
            # 从数据库删除用户
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                c.execute("DELETE FROM user_privileges WHERE user_id = ?", (user_id,))
                conn.commit()
                
                if c.rowcount > 0:
                    response = (
                        f"✅ 已删除用户\n"
                        f"└ ID: `{user_id}`"
                    )
                    # 发送回复消息并安排自动删除
                    msg = update.message.reply_text(response, parse_mode="Markdown")
                    self.auto_delete_message(context, chat_id, msg.message_id, 5)
                    # 删除管理员发送的命令消息
                    try:
                        context.bot.delete_message(chat_id=chat_id, message_id=message_id)
                    except Exception as e:
                        logger.warning(f"无法删除命令消息: {e}")
                else:
                    msg = update.message.reply_text(f"❌ 用户不存在: {user_id}")
                    self.auto_delete_message(context, chat_id, msg.message_id, 5)

        except ValueError:
            msg = update.message.reply_text("❌ 无效的用户ID格式")
            self.auto_delete_message(context, chat_id, msg.message_id, 5)
        except Exception as e:
            logger.error(f"删除用户失败: {e}")
            msg = update.message.reply_text(f"❌ 删除失败: {e}")
            self.auto_delete_message(context, chat_id, msg.message_id, 5)
    
    def info_command(self, update: Update, context: CallbackContext):
        """处理/info命令 - 优化版用户信息"""
        user = update.message.from_user
        user_id = user.id
        chat_id = update.message.chat_id
        chat_type = update.message.chat.type

        # 在群聊中删除用户发送的/info消息
        if chat_type in ['group', 'supergroup']:
            try:
                context.bot.delete_message(chat_id=chat_id, message_id=update.message.message_id)
            except Exception:
                pass

        # 获取用户权限信息
        user_info = self.get_user_privilege(user_id)
        # 检查用户是否已注册
        if user_id not in self.allowed_user_ids and not user_info:
            message = "❌ 您尚未注册，无法使用此功能\n请联系管理员添加您的账户"
            self.send_auto_delete_message(update, context, message, delay=5)
            return
        
        username = f"@{user.username}" if user.username else "未设置"
        first_name = user.first_name or ""
        last_name = user.last_name or ""
        full_name = f"{first_name} {last_name}".strip()          
        
        # 获取导出历史
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                # 今日导出次数
                today = datetime.now().strftime("%Y-%m-%d")
                c.execute("SELECT SUM(folder_count) FROM export_history WHERE user_id = ? AND DATE(export_date) = ?", 
                          (user_id, today))
                today_export = c.fetchone()[0] or 0
                
                # 总导出次数
                c.execute("SELECT SUM(folder_count) FROM export_history WHERE user_id = ?", (user_id,))
                total_export = c.fetchone()[0] or 0
                
                # 最后导出时间
                c.execute("SELECT MAX(export_date) FROM export_history WHERE user_id = ?", (user_id,))
                last_export = c.fetchone()[0]

                if user_info:
                    join_date = user_info.get("join_date")
                else:
                    c.execute("SELECT MIN(export_date) FROM export_history WHERE user_id = ?", (user_id,))
                    join_date_row = c.fetchone()
                    join_date = join_date_row[0] if join_date_row[0] else None                     
        except Exception as e:
            logger.error(f"查询导出历史失败: {e}")
            today_export = 0
            total_export = 0
            last_export = None
            join_date = None

        # 计算下次重置时间（UTC时间次日0点）
        now_utc = datetime.now(timezone.utc)
        reset_time = datetime(
            now_utc.year, 
            now_utc.month, 
            now_utc.day,
            tzinfo=timezone.utc
        ) + timedelta(days=1)

        def format_time(dt):
            if not dt:
                return "从未导出"
            if isinstance(dt, str):
                dt = datetime.fromisoformat(dt)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # 确定用户状态
        if user_id in self.allowed_user_ids:
            status = "👑 管理员"
            status_desc = "拥有所有权限"
            export_limit = "无限制"
            remaining = "无限制"
        elif user_info and user_info.get("privilege_level") == "svip":
            status = "🌟 SVIP用户"
            status_desc = "高级特权用户"
            export_limit = "无限制"
            remaining = "无限制"
        else:
            status = "👤 普通用户"
            status_desc = "基础权限用户"
            remaining = max(0, DAILY_EXPORT_LIMIT - today_export)
            export_limit = f"{DAILY_EXPORT_LIMIT} 个/天 (剩余: {remaining})"

        # 构建用户信息消息
        message_parts = [
            f"<b>👤 用户信息</b>",
            "══════════════════════",
            f"<b>├ 用户ID:</b> <code>{user_id}</code>",
            f"<b>├ 用户名:</b> {username}",
        ]

        if full_name:
            message_parts.append(f"<b>├ 显示名称:</b> {full_name}")

        message_parts.extend([
            f"<b>├ 状态:</b> {status}",
            f"<b>├ 状态描述:</b> {status_desc}",
            "══════════════════════",
            f"<b>├ 导出权限:</b>",
            f"   ├ 今日导出: <b>{today_export}</b> 个JSON文件",
            f"   ├ 剩余次数: <b>{remaining}</b>",
            f"   ├ 总导出次数: <b>{total_export}</b>",
            f"   ├ 权限限制: {export_limit}",
            f"   ├ 最后导出时间: {format_time(last_export)}",
            f"   └ 下次重置: {reset_time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "══════════════════════",
        ])
        if join_date:
            message_parts.append(f"<b>└ 加入时间:</b> {format_time(join_date)}")
        else:
            message_parts.append(f"<b>└ 加入时间:</b> 未知")

        # 添加提示信息
        if status == "👤 普通用户":
            if today_export >= DAILY_EXPORT_LIMIT:
                message_parts.append(f"\n⚠️ <i>您的今日导出次数已达上限({DAILY_EXPORT_LIMIT}次)，请明天再试</i>")
            else:
                message_parts.append(f"\nℹ️ <i>作为普通用户，您每天可导出最多 {DAILY_EXPORT_LIMIT} 个JSON文件</i>")
            message_parts.append("\n💎 <i>联系管理员升级SVIP可享受无限制导出权限</i>")

        # 组合所有消息部分
        message = "\n".join(message_parts)
        self.send_auto_delete_message(update, context, message, delay=10, parse_mode="HTML")

    @admin_required
    def refresh_token_command(self, update: Update, context: CallbackContext):
        """处理/refresh_token命令 - 强制刷新Token"""
        try:
            # 强制获取新Token
            if self.pan_client.token_manager.get_new_token():
                # 获取新的Token信息
                new_token = self.pan_client.token_manager.access_token
                new_expiry = self.pan_client.token_manager.token_expiry
                
                # 构建响应消息
                message = (
                    "✅ Token 强制刷新成功！\n"
                    f"├ 新Token: `{new_token[:12]}...{new_token[-12:]}`\n"
                    f"└ 有效期至: {new_expiry.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                )
            else:
                message = "❌ Token 刷新失败，请检查日志"
                
            update.message.reply_text(message, parse_mode="Markdown")
            
            # 删除用户消息（如果是群聊）
            if update.message.chat.type in ['group', 'supergroup']:
                try:
                    context.bot.delete_message(
                        chat_id=update.message.chat_id,
                        message_id=update.message.message_id
                    )
                except Exception:
                    pass
                    
        except Exception as e:
            logger.error(f"刷新Token失败: {e}")
            self.send_auto_delete_message(update, context, f"❌ 刷新Token失败: {e}")

def main():
    # 添加授权信息提示
    logger.info("=============================================")
    logger.info("123云盘机器人 - 专业版")
    logger.info(f"版本: {VERSION}")
    logger.info("授权验证通过，正在启动服务...")
    logger.info("=============================================")
    # 从环境变量读取配置
    BOT_TOKEN = os.getenv("TG_BOT_TOKEN","")
    CLIENT_ID = os.getenv("PAN_CLIENT_ID","")
    CLIENT_SECRET = os.getenv("PAN_CLIENT_SECRET","")
    ADMIN_USER_IDS = [int(id.strip()) for id in os.getenv("TG_ADMIN_USER_IDS", "").split(",") if id.strip()]
    
    if not BOT_TOKEN:
        logger.error("❌ 环境变量 TG_BOT_TOKEN 未设置")
        return
    
    if not CLIENT_ID:
        logger.error("❌ 环境变量 PAN_CLIENT_ID 未设置")
        return
    
    if not CLIENT_SECRET:
        logger.error("❌ 环境变量 PAN_CLIENT_SECRET 未设置")
        return

    # ========== 添加方案四：禁用 SSL 验证 ==========
    try:
        import ssl
        # 禁用 SSL 验证（解决 UNEXPECTED_EOF_WHILE_READING 错误）
        ssl._create_default_https_context = ssl._create_unverified_context
        #logger.warning("⚠️ 已全局禁用 SSL 证书验证（注意安全风险）")
    except Exception as e:
        logger.error(f"禁用 SSL 验证失败: {e}")
    # ========== 结束添加 ==========
    
    logger.info("初始化123云盘客户端...")
    pan_client = Pan123Client(CLIENT_ID, CLIENT_SECRET)
    
    if not pan_client.token_manager.access_token:
        logger.error("❌ 无法获取有效的Token")
        return
    
    logger.info("初始化Telegram机器人...")
    bot_handler = TelegramBotHandler(BOT_TOKEN, pan_client, ADMIN_USER_IDS)
    bot_handler.start()

if __name__ == "__main__":
    main()
