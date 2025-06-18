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
from urllib.parse import urlparse, parse_qs

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
    "GET_SHARE": "/b/api/share/get",  # 添加分享链接接口
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

# API速率控制配置
API_RATE_LIMIT = float(os.getenv("API_RATE_LIMIT", "2.0"))
TRANSFER_RATE_LIMIT = float(os.getenv("TRANSFER_RATE_LIMIT", "3"))

# 允许的文件类型配置
ALLOWED_VIDEO_EXTENSIONS = [ext.strip().lower() for ext in os.getenv("ALLOWED_VIDEO_EXT", ".mp4,.mkv,.avi,.mov,.flv,.wmv,.webm,.ts,.m2ts,.iso,.mp3,.flac,.wav").split(',') if ext.strip()]
ALLOWED_SUB_EXTENSIONS = [ext.strip().lower() for ext in os.getenv("ALLOWED_SUB_EXT", ".srt,.ass,.ssa,.sub,.idx,.vtt,.sup").split(',') if ext.strip()]

# =====================================================

def init_db():
    """初始化数据库"""
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS token_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                access_token TEXT NOT NULL,
                client_id TEXT NOT NULL,
                client_secret TEXT NOT NULL,
                expired_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS directory_cache (
                file_id INTEGER PRIMARY KEY,
                filename TEXT NOT NULL,
                parent_id INTEGER NOT NULL,
                full_path TEXT NOT NULL,
                base_dir_id INTEGER NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            c.execute('''CREATE INDEX IF NOT EXISTS idx_filename ON directory_cache (filename)''')
            c.execute('''CREATE INDEX IF NOT EXISTS idx_full_path ON directory_cache (full_path)''')
            c.execute('''CREATE INDEX IF NOT EXISTS idx_base_dir ON directory_cache (base_dir_id)''')
            
            conn.commit()
    except Exception as e:
        logger.error(f"数据库初始化失败: {str(e)}")

init_db()

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
                    
                    if (expired_at > now + timedelta(minutes=5) and
                        self.client_id == cached_id and 
                        self.client_secret == cached_secret):
                        
                        self.access_token = token
                        self.token_expiry = expired_at
                        logger.info("使用缓存Token")
                        return True
        except Exception:
            pass
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
        except Exception:
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
                logger.error(f"认证失败: {response.status_code}")
                return False
            
            data = response.json()
            if data.get("code") != 0:
                logger.error(f"API错误: {data.get('code')} - {data.get('message')}")
                return False
            
            self.access_token = data["data"]["accessToken"]
            expired_at_str = data["data"]["expiredAt"]
            
            if expired_at_str.endswith('Z'):
                self.token_expiry = datetime.fromisoformat(expired_at_str[:-1]).replace(tzinfo=timezone.utc)
            elif '+' in expired_at_str or '-' in expired_at_str:
                dt = datetime.fromisoformat(expired_at_str)
                self.token_expiry = dt.astimezone(timezone.utc)
            else:
                self.token_expiry = datetime.fromisoformat(expired_at_str).replace(tzinfo=timezone.utc)
            
            if self.save_token_to_cache(self.access_token, self.token_expiry):
                logger.info(f"更新Token成功，有效期至: {self.token_expiry} (UTC)")
                return True
            return False
        except Exception as e:
            logger.error(f"获取Token失败: {str(e)}")
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
        self.share_root_folder = ""  # 添加这个属性
        
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
            logger.error(f"搜索目录出错: {str(e)}")
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
                    wait_time = float(retry_after) if retry_after else 5.0  # 减少等待时间
                    logger.warning(f"API限流，等待 {wait_time} 秒后重试...")
                    time.sleep(wait_time)
                    retry_count += 1  # 增加重试计数
                    continue
                
                try:
                    data = response.json()
                    if data.get("code") == 429 or "操作频繁" in data.get("message", ""):
                        logger.warning("API限流（内容检测），等待5秒后重试...")
                        time.sleep(5.0)
                        retry_count += 1  # 增加重试计数
                        continue
                except:
                    pass
                
                return response
                
            except (requests.exceptions.SSLError, 
                    requests.exceptions.ConnectionError,
                    requests.exceptions.ChunkedEncodingError,
                    requests.exceptions.HTTPError) as e:
                retry_count += 1
                logger.error(f"网络连接错误: {str(e)}，重试 {retry_count}/{max_retries}")
                time.sleep(2 ** retry_count)
            except ConnectionResetError as e:
                retry_count += 1
                logger.error(f"连接被重置: {str(e)}，重试 {retry_count}/{max_retries}")
                time.sleep(5)
            except Exception as e:
                logger.error(f"API调用出错: {str(e)}")
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
            logger.error(f"获取用户信息出错: {str(e)}")
            return None
    
    def create_folder(self, parent_id, folder_name, retry_count=3):
        """创建文件夹"""
        logger.info(f"创建文件夹: '{folder_name}' (父ID: {parent_id})")
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
                logger.error(f"创建文件夹过程中出错: {str(e)}")
            time.sleep(1)
        return None
    
    def rapid_upload(self, etag, size, file_name, parent_id, max_retries=8):
        """秒传文件"""
        logger.info(f"尝试秒传文件: '{file_name}' (大小: {size} bytes, 父ID: {parent_id})")
        original_etag = etag
        
        if len(etag) != 32 or not all(c in '0123456789abcdef' for c in etag.lower()):
            logger.info(f"转换Etag格式: {etag}")
            etag = FastLinkProcessor.optimized_etag_to_hex(etag, True)
        
        base_delay = 2.0
        max_delay = 180.0
        
        for attempt in range(max_retries):
            try:
                delay = min(max_delay, base_delay * (2 ** attempt))
                if attempt > 0:
                    logger.warning(f"秒传失败，等待 {delay:.1f} 秒后重试 (尝试 {attempt+1}/{max_retries})...")
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
                        logger.info(f"尝试使用原始Etag: {original_etag}")
                        etag = original_etag
                        continue
                    if "操作频繁" in error_msg or "限流" in error_msg or "频繁" in error_msg:
                        with self.rate_limit_lock:
                            self.api_rate_limit = max(0.8, self.api_rate_limit * 0.9)
                        logger.warning(f"触发限流，降低全局速率至 {self.api_rate_limit:.2f} 请求/秒")
                        continue
            except Exception as e:
                logger.error(f"秒传过程中出错: {str(e)}")
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
            logger.error(f"加载目录缓存失败: {str(e)}")
    
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
            logger.error(f"更新目录缓存失败: {str(e)}")
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
            logger.info("已清空内存缓存")
            update_count = 0
            
            for base_dir_id in self.export_base_dir_ids:
                base_dir_path = self.export_base_dir_map.get(base_dir_id, f"基目录({base_dir_id})")
                update_count += self.sync_directory(base_dir_id, base_dir_path, base_dir_id)
            
            logger.info(f"全量同步完成，更新 {update_count} 个目录")
            return update_count
        except Exception as e:
            logger.error(f"全量同步失败: {str(e)}")
            return 0
    
    def sync_directory(self, directory_id, current_path, base_dir_id, current_depth=0):
        """同步指定目录及其子目录"""
        logger.info(f"开始同步目录: '{current_path}' (ID: {directory_id}, 深度: {current_depth})")
        update_count = 0
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
                logger.error(f"同步目录出错: {str(e)}")
                break
        
        logger.info(f"同步完成: '{current_path}' (ID: {directory_id}), 更新 {update_count} 个目录")
        return update_count
    
    def get_directory_files(self, directory_id=0, base_path="", current_path=""):
        """获取目录下的所有文件"""
        logger.info(f"获取目录内容 (ID: {directory_id}, 基础路径: '{base_path}', 当前路径: '{current_path}')")
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
                logger.error(f"获取目录列表出错: {str(e)}")
                return all_files
        
        logger.info(f"找到 {len(all_files)} 个文件 (ID: {directory_id})")
        return all_files

    def clear_trash(self):
        """清空回收站"""
        logger.info("清空回收站中...")
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
            logger.error(f"清空回收站出错: {str(e)}")
            return False
   
    def extract_share_info(self, share_url):
        """从分享链接提取分享Key和密码（使用改进的正则）"""
        # 使用提供的正则表达式
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
            logger.info(f"开始转存分享: key={share_key}, password={password}")
            
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
                        logger.info(f"创建目录: {current_path} (ID: {folder['FileId']})")
                        parent_id = folder["FileId"]
                    else:
                        logger.warning(f"创建目录失败: {current_path}")
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
                        logger.info(f"文件转存成功: {file_path}")
                    else:
                        failure_count += 1
                        results.append({
                            "success": False,
                            "file_name": file_path,
                            "size": file_info["size"],
                            "error": "秒传失败"
                        })
                        logger.warning(f"文件秒传失败: {file_path}")
                except Exception as e:
                    failure_count += 1
                    results.append({
                        "success": False,
                        "file_name": file_path,
                        "size": file_info["size"],
                        "error": str(e)
                    })
                    logger.error(f"文件转存出错: {file_path} - {str(e)}")
            
            return success_count, failure_count, results, total_size
        except Exception as e:
            logger.error(f"保存分享文件失败: {str(e)}")
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
                    item["Type"] = item.get("Type", 0)  # 确保有Type字段
                    items.append(item)
                
                # 检查是否有下一页
                next_marker = data["data"].get("Next", "-1")
                page += 1
                
            except Exception as e:
                logger.error(f"获取分享文件时出错: {str(e)}")
                break
        
        logger.info(f"获取到 {len(items)} 个分享项目 (fid={fid})")
        return items

class FastLinkProcessor:
    @staticmethod
    def parse_share_link(share_link):
        """解析秒传链接"""
        logger.info("解析秒传链接...")
        common_base_path = ""
        is_common_path_format = False
        is_v2_etag_format = False
        
        if share_link.startswith(COMMON_PATH_LINK_PREFIX_V2):
            is_common_path_format = True
            is_v2_etag_format = True
            share_link = share_link[len(COMMON_PATH_LINK_PREFIX_V2):]
        elif share_link.startswith(COMMON_PATH_LINK_PREFIX_V1):
            is_common_path_format = True
            share_link = share_link[len(COMMON_PATH_LINK_PREFIX_V1):]
        elif share_link.startswith(LEGACY_FOLDER_LINK_PREFIX_V2):
            is_v2_etag_format = True
            share_link = share_link[len(LEGACY_FOLDER_LINK_PREFIX_V2):]
        elif share_link.startswith(LEGACY_FOLDER_LINK_PREFIX_V1):
            share_link = share_link[len(LEGACY_FOLDER_LINK_PREFIX_V1):]
        
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
        
        logger.info(f"解析到 {len(files)} 个文件")
        return files
    
    @staticmethod
    def optimized_etag_to_hex(optimized_etag, is_v2_etag):
        """将优化后的ETag转换为十六进制格式"""
        if not is_v2_etag:
            return optimized_etag
        
        try:
            if len(optimized_etag) == 32 and all(c in '0123456789abcdefABCDEF' for c in optimized_etag):
                return optimized_etag.lower()
            
            num = 0
            for char in optimized_etag:
                if char not in BASE62_CHARS:
                    return optimized_etag
                num = num * 62 + BASE62_CHARS.index(char)
            
            hex_str = hex(num)[2:].lower()
            if len(hex_str) > 32:
                hex_str = hex_str[-32:]
            elif len(hex_str) < 32:
                hex_str = hex_str.zfill(32)
            
            if len(hex_str) != 32 or not all(c in '0123456789abcdef' for c in hex_str):
                return optimized_etag
            return hex_str
        except Exception as e:
            logger.error(f"ETag转换失败: {str(e)}")
            return optimized_etag

class TelegramBotHandler:
    def __init__(self, token, pan_client, allowed_user_ids):
        self.token = token
        self.pan_client = pan_client
        self.allowed_user_ids = allowed_user_ids
        self.updater = Updater(token, use_context=True)
        self.dispatcher = self.updater.dispatcher
        self.start_time = pan_client.token_manager.start_time
        
        # 注册处理程序
        self.dispatcher.add_handler(CommandHandler("start", self.start_command))
        self.dispatcher.add_handler(CommandHandler("export", self.export_command))
        self.dispatcher.add_handler(CommandHandler("sync_full", self.sync_full_command))
        self.dispatcher.add_handler(CommandHandler("clear_trash", self.clear_trash_command))
        self.dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, self.handle_text))
        self.dispatcher.add_handler(MessageHandler(Filters.document, self.handle_document))
        self.dispatcher.add_handler(CallbackQueryHandler(self.button_callback))
        
        # 设置菜单命令
        self.set_menu_commands()
    
    def set_menu_commands(self):
        """设置Telegram Bot菜单命令"""
        commands = [
            BotCommand("start", "用户信息"),
            BotCommand("export", "导出秒传文件"),
            BotCommand("sync_full", "全量同步"),
            BotCommand("clear_trash", "清空回收站"),
        ]
        
        try:
            self.updater.bot.set_my_commands(commands)
            logger.info("已设置Telegram Bot菜单命令")
        except Exception as e:
            logger.error(f"设置菜单命令失败: {str(e)}")
    
    def start(self):
        """启动机器人"""
        try:
            self.updater.start_polling()
            logger.info("🤖 机器人已启动，等待消息...")
            logger.info(f"管理员用户ID: {self.allowed_user_ids}")
            self.updater.idle()
        except Exception as e:
            logger.error(f"启动机器人失败: {str(e)}")
    
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
        """自动删除消息"""
        def delete():
            try:
                context.bot.delete_message(chat_id=chat_id, message_id=message_id)
            except Exception:
                pass
        threading.Timer(delay, delete).start()
    
    def send_auto_delete_message(self, update, context, text, delay=3, chat_id=None):
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
        
        message = context.bot.send_message(chat_id=chat_id, text=text)
        self.auto_delete_message(context, chat_id, message.message_id, delay)
        return message
    
    @admin_required
    def start_command(self, update: Update, context: CallbackContext):
        """处理/start命令"""
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
            def format_size(size_bytes):
                if size_bytes >= 1024 ** 4:
                    return f"{size_bytes / (1024 ** 4):.2f} TB"
                elif size_bytes >= 1024 ** 3:
                    return f"{size_bytes / (1024 ** 3):.2f} GB"
                elif size_bytes >= 1024 ** 2:
                    return f"{size_bytes / (1024 ** 2):.2f} MB"
                else:
                    return f"{size_bytes / 1024:.2f} KB"
            
            space_permanent = format_size(user_info.get("spacePermanent", 0))
            space_used = format_size(user_info.get("spaceUsed", 0))
            direct_traffic = format_size(user_info.get("directTraffic", 0))
            
            # 构建消息
            export_dirs = ", ".join(EXPORT_BASE_DIRS) if EXPORT_BASE_DIRS else "根目录"
            message = (
                f"🚀 123云盘用户信息 | {'👑 尊享账户' if user_info.get('vip', False) else '🔒 普通账户'}\n"
                f"══════════════════════\n"
                f"👤 昵称: {user_info.get('nickname', '未知')}\n"
                f"🆔 账户ID: {uid}\n"
                f"📱 手机号码: {phone}\n\n"
                f"💾 存储空间\n"
                f"├ 永久: {space_permanent}\n"
                f"└ 已用: {space_used}\n\n"
                f"📡 流量信息\n"
                f"└ 直链: {direct_traffic}\n"
                f"══════════════════════\n\n"
                f"⚙️ 当前配置:\n"
                f"├ 保存目录: {DEFAULT_SAVE_DIR or '根目录'}\n"
                f"├ 导出目录: {export_dirs}\n"
                f"├ 搜索深度: {SEARCH_MAX_DEPTH}层\n"
                f"└ 数据缓存: {len(self.pan_client.directory_cache)}\n\n"
                f"🤖 机器人控制中心\n"
                f"▫️ /export 导出文件\n"
                f"▫️ /sync_full 全量同步\n"
                f"▫️ /clear_trash 清空回收站\n\n"
                f"⏱️ 已运行: {days}天{hours}小时{minutes}分{seconds}秒\n"
                f"📦 Version: {VERSION}"
            )

            update.message.reply_text(message)
            logger.info("已发送用户信息")
        except Exception as e:
            logger.error(f"处理/start命令出错: {str(e)}")
            self.send_auto_delete_message(update, context, "❌ 获取用户信息失败")

    def search_database_by_name(self, name_pattern):
        """在数据库中进行模糊搜索"""
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("SELECT * FROM directory_cache WHERE filename LIKE ? ORDER BY filename", (f'%{name_pattern}%',))
                rows = c.fetchall()
                logger.info(f"数据库中找到 {len(rows)} 个匹配项: '{name_pattern}'")
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"数据库搜索失败: {str(e)}")
            return []

    @admin_required
    def export_command(self, update: Update, context: CallbackContext):
        """处理/export命令"""
        search_query = " ".join(context.args) if context.args else ""
        if not search_query:
            self.send_auto_delete_message(update, context, "❌ 请指定文件夹名称！格式: /export <文件夹名称>")
            return
        
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
                InlineKeyboardButton("❌ 取消全选", callback_data="export_deselect_all"),
                InlineKeyboardButton("🚀 开始导出", callback_data="export_confirm"),
                InlineKeyboardButton("❌ 取消操作", callback_data="export_cancel")
            ]
            
            keyboard.append(action_buttons[:2])
            keyboard.append(action_buttons[2:])
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            message = update.message.reply_text(f"✅ 找到 {len(results)} 个匹配项\n请选择要导出的文件夹:", reply_markup=reply_markup)
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
            logger.error(f"搜索文件夹失败: {str(e)}")
            self.send_auto_delete_message(update, context, f"❌ 搜索失败: {str(e)}")

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
            InlineKeyboardButton("❌ 取消全选", callback_data="export_deselect_all"),
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
        keys_to_remove = ['export_search_results', 'export_selected_indices', 'export_message_id']
        for key in keys_to_remove:
            if key in user_data:
                del user_data[key]
    
    def process_export_selection(self, update: Update, context: CallbackContext, selected_indices):
        """处理选择的导出任务，添加消息撤回"""
        query = update.callback_query
        results = context.user_data.get('export_search_results', [])
        if not results or not selected_indices:
            query.edit_message_text("❌ 请至少选择一个文件夹")
            return
            
        # 发送临时消息并设置自动删除
        query.edit_message_text(f"⏳ 开始导出 {len(selected_indices)} 个文件夹...")
        self.auto_delete_message(context, query.message.chat_id, query.message.message_id, 3)
        
        if 'export_message_id' in context.user_data:
            message_id = context.user_data['export_message_id']
            job_name = f"export_timeout_{message_id}"
            for job in context.job_queue.get_jobs_by_name(job_name):
                job.schedule_removal()
        
        total = len(selected_indices)
        # 用于存储所有进度消息的ID
        progress_messages = []
        
        for i, idx in enumerate(selected_indices):
            selected_folder = results[idx]
            folder_id = selected_folder["file_id"]
            folder_name = selected_folder["filename"]
            folder_path = selected_folder["full_path"]
            
            logger.info(f"处理文件夹 [{i+1}/{total}]: {folder_name} (ID: {folder_id})")
            
            # 每处理3个文件夹更新一次进度
            if i % 3 == 0:
                try:
                    # 发送进度消息并记录消息ID
                    msg = context.bot.send_message(
                        chat_id=query.message.chat_id,
                        text=f"⏳ 正在处理文件夹 [{i+1}/{total}]:\n"
                             f"├ 名称: {folder_name}\n"
                             f"└ 路径: {folder_path}"
                    )
                    progress_messages.append(msg.message_id)
                except Exception as e:
                    logger.warning(f"发送进度消息失败: {str(e)}")
            
            files = self.pan_client.get_directory_files(folder_id, folder_name)
            if not files:
                logger.warning(f"文件夹为空: {folder_name}")
                continue
            
            logger.info(f"文件夹 '{folder_name}' 中找到 {len(files)} 个文件")
            
            json_data = {
                "commonPath": folder_name,
                "usesBase62EtagsInExport": False,
                "files": [
                    {"path": file_info["path"], "etag": file_info["etag"], "size": file_info["size"]}
                    for file_info in files
                ]
            }
            
            clean_folder_name = re.sub(r'[\\/*?:"<>|]', "", folder_name)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_name = f"{clean_folder_name}_{timestamp}.json"
            
            with open(file_name, "w", encoding="utf-8") as f:
                json.dump(json_data, f, ensure_ascii=False, indent=2)
            
            user_info = self.pan_client.get_user_info()
            nickname = user_info.get("nickname", "未知用户") if user_info else "未知用户"
            caption = (
                f"✨来自：{nickname}的分享\n\n"
                f"📁 文件名: {clean_folder_name}\n"
                f"📝 文件数: {len(files)}\n\n"
                f"❤️ 123因您分享更完美！"
            )
            
            with open(file_name, "rb") as f:
                context.bot.send_document(
                    chat_id=query.message.chat_id,
                    document=f,
                    filename=file_name,
                    caption=caption
                )
            
            os.remove(file_name)
            logger.info(f"已发送导出文件: {file_name}")
        
        # 导出完成后删除所有进度消息
        chat_id = query.message.chat_id
        for msg_id in progress_messages:
            try:
                context.bot.delete_message(chat_id=chat_id, message_id=msg_id)
            except Exception as e:
                logger.warning(f"删除进度消息失败: {str(e)}")
        
        #context.bot.send_message(chat_id=chat_id, text=f"✅ 导出完成！共处理 {total} 个文件夹")
        self.cleanup_export_context(context.user_data)
 
    @admin_required
    def handle_document(self, update: Update, context: CallbackContext):
        """处理文档消息"""
        document = update.message.document
        file_name = document.file_name
        
        if document.mime_type != "application/json" and not file_name.endswith(".json"):
            self.send_auto_delete_message(update, context, "❌ 请发送JSON格式的文件！")
            return
        
        logger.info(f"收到JSON文件: {file_name}")
        self.send_auto_delete_message(update, context, "📥 收到JSON文件，开始下载并解析...")
        
        file = context.bot.get_file(document.file_id)
        file_path = f"temp_{document.file_id}.json"
        file.download(file_path)
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                json_data = json.load(f)
            os.remove(file_path)
            logger.info(f"解析JSON文件: {file_name}")
            self.process_json_file(update, context, json_data)
        except Exception as e:
            logger.error(f"处理JSON文件出错: {str(e)}")
            self.send_auto_delete_message(update, context, f"❌ 处理JSON文件时出错: {str(e)}")
    
    @admin_required
    def process_fast_link(self, update: Update, context: CallbackContext, share_link):
        """处理秒传链接转存"""
        try:
            logger.info(f"处理秒传链接: {share_link[:50]}...")
            files = FastLinkProcessor.parse_share_link(share_link)
            if not files:
                logger.warning("无法解析秒传链接或链接中无有效文件信息")
                self.send_auto_delete_message(update, context, "❌ 无法解析秒传链接")
                return
            
            logger.info(f"开始转存 {len(files)} 个文件...")
            self.send_auto_delete_message(update, context, f"✅ 解析成功！找到 {len(files)} 个文件，开始转存...")
            results, filtered_count, elapsed_time, original_total_count, original_total_size = self.transfer_files(update, context, files)
            self.send_transfer_results(update, context, results, filtered_count, elapsed_time, original_total_count, original_total_size)
        except Exception as e:
            logger.error(f"处理秒传链接出错: {str(e)}")
            self.send_auto_delete_message(update, context, f"❌ 处理秒传链接时出错: {str(e)}")
    
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
            
            logger.info(f"开始转存 {len(files)} 个文件...")
            self.send_auto_delete_message(update, context, f"✅ 解析成功！找到 {len(files)} 个文件，开始转存...")
            results, filtered_count, elapsed_time, original_total_count, original_total_size = self.transfer_files(update, context, files)
            self.send_transfer_results(update, context, results, filtered_count, elapsed_time, original_total_count, original_total_size)
        except Exception as e:
            logger.error(f"处理JSON文件出错: {str(e)}")
            self.send_auto_delete_message(update, context, f"❌ 处理JSON文件时出错: {str(e)}")
    
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
        
        logger.info(f"开始转存 {original_total_count} 个文件...")
        
        for i, file_info in enumerate(files):
            file_path = file_info["file_name"]
            file_size = file_info["size"]
            
            if not is_allowed_file(file_path):
                logger.info(f"跳过非视频/字幕文件: {file_path}")
                filtered_count += 1
                continue
                
            # 每处理10个文件显示一次进度
            if i % 10 == 0:
                logger.info(f"处理文件 [{i+1}/{original_total_count}]: {file_path}")
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
                    "error": f"网络错误: {str(e)}"
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
        logger.info(f"文件转存完成，成功: {sum(1 for r in results if r['success'])}, 失败: {len(results) - sum(1 for r in results if r['success'])}")
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
            f"├ 文件大小: {original_total_size_gb:.2f} GB\n"
            f"├ 成功数量: {success_count} (大小: {success_size_gb:.2f} GB)\n"
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
        logger.info("已发送转存结果")
    
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
        logger.info("收到/sync_full命令")

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
                logger.info("全量同步已取消")

    def execute_full_sync(self, update: Update, context: CallbackContext):
        """执行全量同步"""
        chat_id = getattr(context, '_chat_id', None)
        self.send_auto_delete_message(update, context, "🔄 正在执行全量同步...", chat_id=chat_id)
        logger.info("开始执行全量同步")
        
        try:
            start_time = time.time()
            update_count = self.pan_client.full_sync_directory_cache()
            elapsed = time.time() - start_time
            self.send_auto_delete_message(
                update, context, 
                f"✅ 全量同步完成！\n├ 更新目录: {update_count} 个\n└ 耗时: {elapsed:.2f}秒",
                chat_id=chat_id
            )
            logger.info(f"全量同步完成，耗时: {elapsed:.2f}秒")
        except Exception as e:
            logger.error(f"全量同步失败: {str(e)}")
            self.send_auto_delete_message(update, context, "❌ 全量同步失败", chat_id=chat_id)
            
        if hasattr(context, '_chat_id'):
            del context._chat_id

    @admin_required
    def clear_trash_command(self, update: Update, context: CallbackContext):
        """处理/clear_trash命令"""
        logger.info("收到/clear_trash命令")
        self.send_auto_delete_message(update, context, "🔄 正在清空回收站...")
        try:
            if self.pan_client.clear_trash():
                self.send_auto_delete_message(update, context, "✅ 回收站已成功清空", delay=5)
                logger.info("回收站已清空")
            else:
                self.send_auto_delete_message(update, context, "❌ 清空回收站失败", delay=5)
                logger.warning("清空回收站失败")
        except Exception as e:
            logger.error(f"清空回收站出错: {str(e)}")
            self.send_auto_delete_message(update, context, "❌ 清空回收站时出错", delay=5)

    @admin_required
    def process_share_link(self, update: Update, context: CallbackContext, share_url):
        """处理123云盘分享链接（保留目录结构）"""
        try:
            logger.info(f"处理分享链接: {share_url}")
            self.send_auto_delete_message(update, context, "🔗 正在解析分享链接...")
            
            # 在后台线程中处理转存
            def do_share_transfer():
                try:
                    start_time = time.time()
                    # 注意：现在返回四个值，包括总大小
                    success, failure, results, total_size = self.pan_client.save_share_files(
                        share_url, 
                        self.pan_client.default_save_dir_id
                    )
                    elapsed = time.time() - start_time
                    
                    # 计算总大小（GB）
                    total_size_gb = total_size / (1024 ** 3)
                    
                    # 构建结果消息
                    message = (
                        f"📦 分享链接转存完成！\n"
                        f"├ 成功: {success} 文件\n"
                        f"├ 失败: {failure} 文件\n"
                        f"├ 总大小: {total_size_gb:.2f} GB\n"
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
                    logger.error(f"处理分享链接出错: {str(e)}")
                    self.send_auto_delete_message(
                        update, context, 
                        f"❌ 处理分享链接时出错: {str(e)}",
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
            logger.error(f"处理分享链接出错: {str(e)}")
            self.send_auto_delete_message(update, context, f"❌ 处理分享链接时出错: {str(e)}")

    @admin_required
    def handle_text(self, update: Update, context: CallbackContext):
        """处理文本消息 - 仅保留秒传链接处理"""
        text = update.message.text.strip()
        
        if (text.startswith(LEGACY_FOLDER_LINK_PREFIX_V1) or 
            text.startswith(LEGACY_FOLDER_LINK_PREFIX_V2) or 
            text.startswith(COMMON_PATH_LINK_PREFIX_V1) or 
            text.startswith(COMMON_PATH_LINK_PREFIX_V2) or
            ('#' in text and '$' in text)):
            self.send_auto_delete_message(update, context, "🔍 检测到秒传链接，开始解析...")
            self.process_fast_link(update, context, text)
        # 处理123云盘分享链接（使用改进的正则匹配）
        elif re.search(r'https?://(?:[a-zA-Z0-9-]+\.)*123[a-zA-Z0-9-]*\.[a-z]{2,6}/s/[a-zA-Z0-9\-_]+', text):
            self.send_auto_delete_message(update, context, "🔗 检测到123云盘分享链接，开始解析...")
            self.process_share_link(update, context, text)

def main():
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
    
    logger.info("初始化123云盘客户端...")
    pan_client = Pan123Client(CLIENT_ID, CLIENT_SECRET)
    
    if not pan_client.token_manager.access_token:
        logger.error("❌ 无法获取有效的Token")
        return
    
    logger.info("初始化Telegram机器人...")
    bot_handler = TelegramBotHandler(BOT_TOKEN, pan_client, ADMIN_USER_IDS)
    logger.info("机器人启动中...")
    bot_handler.start()

if __name__ == "__main__":
    main()
