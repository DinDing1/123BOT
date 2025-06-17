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
import binascii
from urllib.parse import urlparse, parse_qs

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
# 数据库文件路径 (使用相对路径)
DB_PATH = os.getenv("DB_PATH", "bot123.db")

# 123云盘API配置
PAN_HOST = "https://www.123pan.com"
API_PATHS = {
    "TOKEN": "/api/v1/access_token",
    "USER_INFO": "/api/v1/user/info",  # 获取用户信息
    "LIST_FILES_V2": "/api/v2/file/list",
    "FILE_INFOS": "/api/v1/file/infos",
    "UPLOAD_REQUEST": "/b/api/file/upload_request",
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
DEFAULT_SAVE_DIR = os.getenv("DEFAULT_SAVE_DIR", "").strip()  # 默认保存目录
EXPORT_BASE_DIRS = [d.strip() for d in os.getenv("EXPORT_BASE_DIR", "").split(';') if d.strip()]  # 多个导出基目录
SEARCH_MAX_DEPTH = int(os.getenv("SEARCH_MAX_DEPTH", ""))         # 搜索文件夹的最大深度
# =====================================================

def init_db():
    """初始化数据库"""
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            # 创建Token缓存表
            c.execute('''CREATE TABLE IF NOT EXISTS token_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                access_token TEXT NOT NULL,
                client_id TEXT NOT NULL,
                client_secret TEXT NOT NULL,
                expired_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            # 创建目录缓存表
            c.execute('''CREATE TABLE IF NOT EXISTS directory_cache (
                file_id INTEGER PRIMARY KEY,
                filename TEXT NOT NULL,
                parent_id INTEGER NOT NULL,
                full_path TEXT NOT NULL,
                base_dir_id INTEGER NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            # 创建索引以加速搜索
            c.execute('''CREATE INDEX IF NOT EXISTS idx_filename ON directory_cache (filename)''')
            c.execute('''CREATE INDEX IF NOT EXISTS idx_full_path ON directory_cache (full_path)''')
            c.execute('''CREATE INDEX IF NOT EXISTS idx_base_dir ON directory_cache (base_dir_id)''')
            
            conn.commit()
            #logger.info(f"数据库初始化完成: {DB_PATH}")
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
        self.start_time = datetime.now()  # 记录启动时间
        
        # 尝试从缓存加载Token
        if not self.load_token_from_cache():
            logger.info("未找到有效缓存Token，将获取新Token")
            self.get_new_token()
    
    def _create_session(self):
        """创建带重试机制的Session"""
        session = requests.Session()
        
        # 配置重试策略
        retry_strategy = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=100,
            pool_maxsize=100
        )
        
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        
        # 禁用SSL验证
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
                    
                    # 检查Token是否有效且凭证未变化
                    if (expired_at > now + timedelta(minutes=5) and
                        self.client_id == cached_id and 
                        self.client_secret == cached_secret):
                        
                        self.access_token = token
                        self.token_expiry = expired_at
                        
                        expires_in = int((expired_at - now).total_seconds())
                        logger.info(
                            "使用缓存Token\n"
                            "├─ 有效期至：%s (UTC)\n"
                            "└─ 剩余时间：%d小时%d分钟",
                            expired_at.strftime("%Y-%m-%d %H:%M:%S"),
                            expires_in // 3600,
                            (expires_in % 3600) // 60
                        )
                        return True
                    else:
                        logger.info("缓存Token无效或已过期")
                else:
                    logger.info("未找到缓存Token")
        except Exception as e:
            logger.error(f"加载缓存Token失败: {str(e)}")
        return False
    
    def save_token_to_cache(self, access_token, expired_at):
        """保存Token到数据库"""
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                # 清除旧Token
                c.execute("DELETE FROM token_cache")
                # 插入新Token
                c.execute('''INSERT INTO token_cache 
                           (access_token, client_id, client_secret, expired_at)
                           VALUES (?,?,?,?)''',
                           (access_token, self.client_id, self.client_secret, expired_at.isoformat()))
                conn.commit()
                logger.info("Token已保存到缓存")
                return True
        except Exception as e:
            logger.error(f"保存Token到缓存失败: {str(e)}")
        return False
    
    def get_new_token(self):
        """获取新token（使用开放平台API）"""
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
            
            response = self.session.post(
                url,
                json=payload,
                headers=headers,
                timeout=20
            )
            
            if response.status_code != 200:
                logger.error(f"认证失败: {response.status_code}")
                return False
            
            data = response.json()
            
            if data.get("code") != 0:
                logger.error(f"API错误: {data.get('code')} - {data.get('message')}")
                return False
            
            # 提取并保存token
            self.access_token = data["data"]["accessToken"]
            
            # 解析过期时间字符串
            expired_at_str = data["data"]["expiredAt"]
            
            # 修复时间解析问题
            if expired_at_str.endswith('Z'):
                self.token_expiry = datetime.fromisoformat(expired_at_str[:-1]).replace(tzinfo=timezone.utc)
            elif '+' in expired_at_str or '-' in expired_at_str:
                dt = datetime.fromisoformat(expired_at_str)
                self.token_expiry = dt.astimezone(timezone.utc)
            else:
                self.token_expiry = datetime.fromisoformat(expired_at_str).replace(tzinfo=timezone.utc)
            
            # 保存到缓存
            if self.save_token_to_cache(self.access_token, self.token_expiry):
                logger.info(f"更新Token\n└─有效期至: {self.token_expiry} (UTC)")
                return True
            else:
                logger.error("Token保存到缓存失败")
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

class Pan123Client:
    def __init__(self, client_id, client_secret):
        self.token_manager = TokenManager(client_id, client_secret)
        self.session = self._create_session()
        self.last_api_call = 0  # 记录最后一次API调用时间
        self.api_rate_limit = 2  # 降低API调用频率
        self.retry_delay = 2.0  # 增加限流时重试延迟（秒）
        
        # 初始化默认目录ID
        self.default_save_dir_id = 0  # 根目录
        self.export_base_dir_ids = []   # 存储多个基目录ID
        self.export_base_dir_map = {0: "根目录"}  # 基目录ID到路径的映射
        
        # 设置默认保存目录
        if DEFAULT_SAVE_DIR:
            self.default_save_dir_id = self.get_or_create_directory(DEFAULT_SAVE_DIR)
            logger.info(f"默认保存目录已设置: '{DEFAULT_SAVE_DIR}' (ID: {self.default_save_dir_id})")
        
        # 设置多个导出基目录
        for base_dir in EXPORT_BASE_DIRS:
            base_dir_id = self.get_or_create_directory(base_dir)
            self.export_base_dir_ids.append(base_dir_id)
            self.export_base_dir_map[base_dir_id] = base_dir
            logger.info(f"导出基目录已设置: '{base_dir}' (ID: {base_dir_id})")
        
        # 设置搜索最大深度
        self.search_max_depth = SEARCH_MAX_DEPTH
        logger.info(f"搜索最大深度已设置: {self.search_max_depth} 层")
        
        # 初始化目录缓存
        self.directory_cache = {}
        self.load_directory_cache()
    
    def _create_session(self):
        """创建带重试机制的Session"""
        session = requests.Session()
        
        # 配置重试策略
        retry_strategy = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=100,
            pool_maxsize=100
        )
        
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        
        # 禁用SSL验证
        session.verify = False
        return session
    
    def get_or_create_directory(self, path):
        """获取或创建目录路径"""
        parent_id = 0  # 从根目录开始
        parts = path.strip('/').split('/')
        
        for part in parts:
            if not part:
                continue
                
            # 搜索目录
            folder_info = self.search_folder(part, parent_id)
            
            if folder_info:
                parent_id = folder_info["fileId"]
                logger.debug(f"找到目录: '{part}' (ID: {parent_id})")
            else:
                # 创建目录
                folder = self.create_folder(parent_id, part)
                if not folder:
                    logger.error(f"无法创建目录: '{part}'")
                    return parent_id  # 返回上一级可用目录
                parent_id = folder["FileId"]
                logger.info(f"已创建目录: '{part}' (ID: {parent_id})")
        
        return parent_id
    
    def search_folder(self, folder_name, parent_id=0):
        """在指定父目录下搜索文件夹（非递归）"""
        try:
            url = f"{OPEN_API_HOST}{API_PATHS['LIST_FILES_V2']}"
            params = {
                "parentFileId": parent_id,
                "trashed": 0,  # 排除回收站文件
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
                
            # 检查当前目录下的文件夹
            for item in data["data"].get("fileList", []):
                if item["type"] == 1 and item["filename"] == folder_name:
                    return {
                        "fileId": item["fileId"],
                        "filename": item["filename"]
                    }
                    
        except Exception as e:
            logger.error(f"搜索目录出错: {str(e)}")
            
        return None

    # 添加API调用控制方法
    def _call_api(self, method, url, **kwargs):
        """控制API调用频率，避免限流"""
        retry_count = 0
        max_retries = 3
        
        while retry_count < max_retries:
            try:
                # 计算距离上次调用的时间
                elapsed = time.time() - self.last_api_call
                required_delay = 1.0 / self.api_rate_limit
                
                # 如果调用过快，等待足够的时间
                if elapsed < required_delay:
                    wait_time = required_delay - elapsed
                    logger.debug(f"API调用过快，等待 {wait_time:.2f} 秒")
                    time.sleep(wait_time)
                
                # 发送API请求
                response = self.session.request(method, url, **kwargs)
                self.last_api_call = time.time()
                
                # 检查是否被限流
                if response.status_code == 429:
                    logger.warning(f"API限流，等待 {self.retry_delay} 秒后重试...")
                    time.sleep(self.retry_delay)
                    continue
                
                return response
                
            except (requests.exceptions.SSLError, requests.exceptions.ConnectionError) as e:
                retry_count += 1
                logger.error(f"❌ SSL/连接错误: {str(e)}，重试 {retry_count}/{max_retries}")
                time.sleep(2 ** retry_count)  # 指数退避
            except Exception as e:
                logger.error(f"API调用出错: {str(e)}")
                return None
        
        logger.error(f"API调用失败，已达到最大重试次数 {max_retries}")
        return None
    
    def _get_auth_headers(self):
        """获取认证头（添加原始脚本中的额外头信息）"""
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
                logger.error("无法获取有效的Token")
                return None
                
            url = f"{OPEN_API_HOST}{API_PATHS['USER_INFO']}"
            headers = self.token_manager.get_auth_header()
            
            # 使用限流保护的API调用
            response = self._call_api("GET", url, headers=headers, timeout=30)
            if not response or response.status_code != 200:
                logger.error(f"获取用户信息失败: HTTP {response.status_code if response else '无响应'}")
                return None
                
            data = response.json()
            if data.get("code") != 0:
                logger.error(f"API错误: {data.get('code')} - {data.get('message')}")
                return None
                
            return data.get("data")
            
        except Exception as e:
            logger.error(f"获取用户信息出错: {str(e)}")
            return None
    
    def create_folder(self, parent_id, folder_name, retry_count=3):
        """创建文件夹（带重试机制）"""
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
                
                # 使用更健壮的请求方式
                response = self.session.post(
                    url, 
                    json=payload, 
                    headers=headers, 
                    timeout=20,
                    verify=False  # 明确禁用SSL验证
                )
                
                data = response.json()
                
                if data.get("code") == 0 and data["data"].get("Info", {}).get("FileId"):
                    folder_id = data["data"]["Info"]["FileId"]
                    logger.info(f"✅ 文件夹创建成功: '{folder_name}' (ID: {folder_id})")
                    return data["data"]["Info"]
                else:
                    error_msg = data.get("message", "未知错误")
                    logger.error(f"❌ 创建文件夹失败: {error_msg}")
                    if attempt < retry_count - 1:
                        time.sleep(1)  # 等待后重试
                        continue
                    return None
            except (requests.exceptions.SSLError, requests.exceptions.ConnectionError) as e:
                logger.error(f"❌ SSL/连接错误: {str(e)}")
                if attempt < retry_count - 1:
                    logger.info(f"等待1秒后重试 ({attempt+1}/{retry_count})...")
                    time.sleep(1)
                    continue
                return None
            except Exception as e:
                logger.error(f"❌ 创建文件夹过程中出错: {str(e)}")
                if attempt < retry_count - 1:
                    time.sleep(1)
                    continue
                return None
        return None
    
    def rapid_upload(self, etag, size, file_name, parent_id, retry_count=3):
        """秒传文件（带重试机制）"""
        logger.info(f"尝试秒传文件: '{file_name}' (大小: {size} bytes, 父ID: {parent_id})")
        
        # 保存原始Etag
        original_etag = etag
        
        # 如果Etag长度是32位且是十六进制，直接使用
        if len(etag) == 32 and all(c in '0123456789abcdef' for c in etag.lower()):
            logger.info(f"Etag是有效的MD5格式: {etag}")
        else:
            # 尝试转换为MD5格式
            etag = FastLinkProcessor.optimized_etag_to_hex(etag, True)
            logger.info(f"转换后Etag: {etag}")
        
        for attempt in range(retry_count):
            try:
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
                
                # 使用更健壮的请求方式
                response = self.session.post(
                    url, 
                    json=payload, 
                    headers=headers, 
                    timeout=20,
                    verify=False  # 明确禁用SSL验证
                )
                
                data = response.json()
                
                if data.get("code") == 0 and data["data"].get("Info", {}).get("FileId"):
                    file_id = data["data"]["Info"]["FileId"]
                    logger.info(f"✅ 文件秒传成功: '{file_name}' (ID: {file_id})")
                    return data["data"]["Info"]
                else:
                    error_msg = data.get("message", "未知错误")
                    logger.error(f"❌ 文件秒传失败: {error_msg}")
                    
                    # 如果是Etag格式问题，尝试使用原始Etag
                    if "etag" in error_msg.lower() and etag != original_etag:
                        logger.info(f"⚠️ 尝试使用原始Etag: {original_etag}")
                        etag = original_etag  # 下次重试使用原始Etag
                        continue
                    
                    if attempt < retry_count - 1:
                        time.sleep(1)
                        continue
                    return None
            except (requests.exceptions.SSLError, requests.exceptions.ConnectionError) as e:
                logger.error(f"❌ SSL/连接错误: {str(e)}")
                if attempt < retry_count - 1:
                    logger.info(f"等待1秒后重试 ({attempt+1}/{retry_count})...")
                    time.sleep(1)
                    continue
                return None
            except Exception as e:
                logger.error(f"❌ 秒传过程中出错: {str(e)}")
                if attempt < retry_count - 1:
                    time.sleep(1)
                    continue
                return None
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
                
                logger.info(f"已加载 {len(rows)} 个目录缓存 (导出基目录ID: {self.export_base_dir_ids})")
        except Exception as e:
            logger.error(f"加载目录缓存失败: {str(e)}")
    
    def update_directory_cache(self, file_id, filename, parent_id, full_path, base_dir_id):
        """更新目录缓存"""
        try:
            # 检查是否已存在
            if file_id in self.directory_cache:
                existing = self.directory_cache[file_id]
                if (existing["filename"] == filename and 
                    existing["parent_id"] == parent_id and 
                    existing["full_path"] == full_path and
                    existing["base_dir_id"] == base_dir_id):
                    return False  # 无变化，无需更新
            
            # 更新内存缓存
            cache_entry = {
                "file_id": file_id,
                "filename": filename,
                "parent_id": parent_id,
                "full_path": full_path,
                "base_dir_id": base_dir_id
            }
            self.directory_cache[file_id] = cache_entry
            
            # 更新数据库
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                # 使用INSERT OR REPLACE确保更新
                c.execute('''INSERT OR REPLACE INTO directory_cache 
                            (file_id, filename, parent_id, full_path, base_dir_id) 
                            VALUES (?,?,?,?,?)''',
                          (file_id, filename, parent_id, full_path, base_dir_id))
                conn.commit()
            
            logger.info(f"更新目录缓存: {filename} (ID: {file_id}, 路径: {full_path}, 基目录ID: {base_dir_id})")
            return True
        except Exception as e:
            logger.error(f"更新目录缓存失败: {str(e)}")
            return False
    
    def remove_from_directory_cache(self, file_id):
        """从缓存中移除目录"""
        try:
            if file_id in self.directory_cache:
                del self.directory_cache[file_id]
            
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                c.execute("DELETE FROM directory_cache WHERE file_id = ?", (file_id,))
                conn.commit()
            
            logger.info(f"已从缓存中移除目录: {file_id}")
            return True
        except Exception as e:
            logger.error(f"从缓存中移除目录失败: {str(e)}")
            return False
    
    def search_in_cache(self, folder_name, parent_id=None):
        """在缓存中搜索目录"""
        results = []
        for file_id, cache in self.directory_cache.items():
            if cache["filename"] == folder_name:
                # 如果指定了父目录ID，则检查是否匹配
                if parent_id is not None and cache["parent_id"] != parent_id:
                    continue
                results.append(cache)
        
        # 按路径长度排序（较短的路径可能更接近根目录）
        results.sort(key=lambda x: len(x["full_path"]))
        
        logger.debug(f"在缓存中找到 {len(results)} 个匹配目录: '{folder_name}'")
        return results
    
    def full_sync_directory_cache(self):
        """全量同步目录缓存"""
        logger.info("开始全量同步目录缓存...")
        
        try:
            update_count = 0
            # 同步根目录
            update_count += self.sync_directory(0, "根目录", base_dir_id=0)
            
            # 同步所有导出基目录
            for base_dir_id in self.export_base_dir_ids:
                base_dir_path = self.export_base_dir_map.get(base_dir_id, f"基目录({base_dir_id})")
                update_count += self.sync_directory(base_dir_id, base_dir_path, base_dir_id=base_dir_id)
                
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
                "trashed": 0,  # 排除回收站文件
                "limit": 100,
                "lastFileId": last_file_id
            }
            headers = self.token_manager.get_auth_header()
            
            try:
                logger.debug(f"请求目录列表: {url}, 参数: {params}")
                response = self._call_api("GET", url, params=params, headers=headers, timeout=30)
                
                if not response or response.status_code != 200:
                    logger.error(f"获取目录列表失败: HTTP {response.status_code if response else '无响应'}")
                    break
                
                data = response.json()
                if data.get("code") != 0:
                    logger.error(f"API错误: {data.get('code')} - {data.get('message')}")
                    break
                
                # 处理当前页的文件
                for item in data["data"].get("fileList", []):
                    # 排除回收站文件
                    if item.get("trashed", 1) != 0:
                        continue
                    
                    # 构建文件路径
                    item_path = f"{current_path}/{item['filename']}" if current_path else item['filename']
                    
                    if item["type"] == 1:  # 文件夹
                        # 更新缓存
                        updated = self.update_directory_cache(
                            item["fileId"],
                            item["filename"],
                            directory_id,
                            item_path,
                            base_dir_id
                        )
                        if updated:
                            update_count += 1
                            logger.info(f"更新目录缓存: {item['filename']} (ID: {item['fileId']}, 路径: {item_path})")
                        
                        # 递归同步子目录（在深度限制内）
                        if current_depth < self.search_max_depth:
                            update_count += self.sync_directory(
                                item["fileId"],
                                item_path,
                                base_dir_id,
                                current_depth + 1
                            )
                
                # 检查是否有更多页面
                last_file_id = data["data"].get("lastFileId", -1)
                if last_file_id == -1:
                    break
                    
            except Exception as e:
                logger.error(f"同步目录出错: {str(e)}", exc_info=True)
                break
        
        logger.info(f"同步完成: '{current_path}' (ID: {directory_id}), 更新 {update_count} 个目录")
        return update_count
    
    def search_folder_recursive(self, folder_name, parent_id=0, current_path="", current_depth=0):
        """递归搜索整个云盘结构中的文件夹（带缓存优先）"""
        # 首先尝试在缓存中搜索
        cached_results = self.search_in_cache(folder_name, parent_id)
        if cached_results:
            # 返回第一个匹配结果
            return {
                "fileId": cached_results[0]["file_id"],
                "filename": cached_results[0]["filename"],
                "path": cached_results[0]["full_path"],
                "from_cache": True
            }
        
        # 如果缓存中没有，再执行递归搜索
        return self._search_folder_recursive(folder_name, parent_id, current_path, current_depth)
    
    def _search_folder_recursive(self, folder_name, parent_id=0, current_path="", current_depth=0):
        """实际递归搜索实现"""
        # 如果当前深度超过最大深度，则停止递归
        if current_depth > self.search_max_depth:
            logger.info(f"已达到最大搜索深度 {self.search_max_depth}，停止递归")
            return None
            
        logger.info(f"搜索文件夹: '{folder_name}' (深度: {current_depth}/{self.search_max_depth}, 父ID: {parent_id}, 当前路径: '{current_path}')")
        
        # 确保token有效
        if not self.token_manager.ensure_token_valid():
            logger.error("无法获取有效的Token")
            return None
        
        # 使用V2 API获取目录内容
        last_file_id = 0
        while True:
            url = f"{OPEN_API_HOST}{API_PATHS['LIST_FILES_V2']}"
            params = {
                "parentFileId": parent_id,
                "trashed": 0,  # 排除回收站文件
                "limit": 100,
                "lastFileId": last_file_id
            }
            headers = self.token_manager.get_auth_header()
            
            try:
                # 使用限流保护的API调用
                response = self._call_api("GET", url, params=params, headers=headers, timeout=30)
                if not response or response.status_code != 200:
                    return None
                
                data = response.json()
                if data.get("code") != 0:
                    return None
                
                # 检查当前目录下的文件夹
                for item in data["data"].get("fileList", []):
                    if item["type"] != 1:  # 跳过非文件夹
                        continue
                        
                    item_path = f"{current_path}/{item['filename']}" if current_path else item['filename']
                    
                    # 检查是否匹配目标文件夹
                    if item["filename"] == folder_name:
                        logger.info(f"✅ 找到文件夹: {folder_name} (ID: {item['fileId']}, 路径: '{item_path}')")
                        
                        # 更新缓存
                        self.update_directory_cache(
                            item["fileId"],
                            item["filename"],
                            parent_id,
                            item_path,
                            # 基目录ID未知，暂时设为0
                            0
                        )
                        
                        return {
                            "fileId": item["fileId"],
                            "filename": item["filename"],
                            "path": item_path,
                            "from_cache": False
                        }
                    
                    # 递归搜索子目录（仅在深度限制内）
                    if current_depth < self.search_max_depth:
                        time.sleep(0.1)  # 增加延迟避免限流
                        found_folder = self._search_folder_recursive(
                            folder_name,
                            item["fileId"],
                            item_path,
                            current_depth + 1
                        )
                        if found_folder:
                            return found_folder
                    else:
                        logger.debug(f"跳过深度 {current_depth+1} 的目录: '{item['filename']}' (超出搜索深度限制)")
                
                # 检查是否有更多页面
                last_file_id = data["data"].get("lastFileId", -1)
                if last_file_id == -1:
                    break
                    
            except Exception as e:
                logger.error(f"搜索文件夹出错: {str(e)}")
                return None
        
        return None
    
    def get_directory_files(self, directory_id=0, base_path="", current_path=""):
        """
        获取目录下的所有文件（使用V2 API）
        base_path: 基础路径（搜索到的文件夹名称）
        current_path: 当前相对路径
        """
        logger.info(f"获取目录内容 (ID: {directory_id}, 基础路径: '{base_path}', 当前路径: '{current_path}')")
        all_files = []
        
        # 确保token有效
        if not self.token_manager.ensure_token_valid():
            logger.error("无法获取有效的Token")
            return []
        
        # 使用V2 API获取目录内容
        last_file_id = 0  # 初始值为0
        while True:
            url = f"{OPEN_API_HOST}{API_PATHS['LIST_FILES_V2']}"
            params = {
                "parentFileId": directory_id,
                "trashed": 0,  # 排除回收站文件
                "limit": 100,   # 最大不超过100
                "lastFileId": last_file_id
            }
            headers = self.token_manager.get_auth_header()
            
            try:
                logger.debug(f"请求目录列表: {url}, 参数: {params}")
                
                # 使用限流保护的API调用
                response = self._call_api("GET", url, params=params, headers=headers, timeout=30)
                if not response:
                    logger.error(f"获取目录列表失败")
                    return all_files
                
                # 调试日志
                logger.debug(f"响应状态码: {response.status_code}")
                if response.status_code != 200:
                    logger.error(f"获取目录列表失败: HTTP {response.status_code}")
                    return all_files
                
                try:
                    data = response.json()
                except json.JSONDecodeError as e:
                    logger.error(f"响应JSON解析失败: {str(e)}")
                    logger.error(f"完整响应: {response.text}")
                    return all_files
                
                if data.get("code") != 0:
                    error_msg = data.get("message", "未知错误")
                    
                    # 如果是限流错误，等待后重试
                    if "操作频繁" in error_msg or "限流" in error_msg:
                        logger.warning(f"API限流: {error_msg}, 等待 {self.retry_delay} 秒后重试...")
                        time.sleep(self.retry_delay)
                        continue
                    
                    logger.error(f"API错误: {error_msg}")
                    return all_files
                
                # 处理当前页的文件
                for item in data["data"].get("fileList", []):
                    # 排除回收站文件
                    if item.get("trashed", 1) != 0:
                        continue
                    
                    # 构建文件相对路径
                    if current_path:
                        file_path = f"{current_path}/{item['filename']}"
                    else:
                        file_path = item['filename']
                    
                    if item["type"] == 0:  # 文件
                        file_info = {
                            "path": file_path,  # 存储完整相对路径
                            "etag": item["etag"],
                            "size": item["size"]
                        }
                        all_files.append(file_info)
                    elif item["type"] == 1:  # 文件夹
                        # 构建子目录路径
                        if current_path:
                            sub_path = f"{current_path}/{item['filename']}"
                        else:
                            sub_path = item['filename']
                        
                        # 递归获取子目录（添加延迟避免限流）
                        time.sleep(0.5)  # 增加延迟
                        sub_files = self.get_directory_files(
                            item["fileId"],
                            base_path,
                            sub_path
                        )
                        all_files.extend(sub_files)
                
                # 检查是否有更多页面
                last_file_id = data["data"].get("lastFileId", -1)
                if last_file_id == -1:
                    break
                    
            except Exception as e:
                logger.error(f"获取目录列表出错: {str(e)}", exc_info=True)
                return all_files
        
        logger.info(f"找到 {len(all_files)} 个文件 (ID: {directory_id})")
        return all_files
    

##########################123分享开始################################
    
    def get_share_files(self, share_key, password="", parent_id=0, page=1, next_page=0):
        """获取单页分享项目（包含所有必需参数）"""
        url = f"{PAN_HOST}/api/share/get"
        params = {
            "ShareKey": share_key,
            "SharePwd": password,
            "limit": 100,
            "Page": page,
            "Next": next_page,
            "parentFileId": parent_id,
            "orderBy": "file_id",
            "orderDirection": "asc",
            "event": "homeListFile",
            "driveId": 0,
            "trashed": "false",
            "inDirectSpace": "false"
        }
        
        try:
            # 使用限流保护的API调用
            response = self._call_api("GET", url, params=params, timeout=30)
            if not response or response.status_code != 200:
                logger.error(f"获取分享内容失败: HTTP {response.status_code if response else '无响应'}")
                return None
                
            data = response.json()
            if data.get("code") != 0:
                logger.error(f"API错误: {data.get('code')} - {data.get('message')}")
                return None
                
            return data.get("data", {})
        except Exception as e:
            logger.error(f"获取分享内容出错: {str(e)}")
            return None
    
    def get_all_share_files(self, share_key, password=""):
        """递归获取分享中的所有文件"""
        all_files = []
        
        def process_folder(parent_id=0, base_path=""):
            next_page = 0
            while True:
                # 获取当前页的内容
                result = self.get_share_files(share_key, password, parent_id, 1, next_page)
                if not result:
                    break
                    
                # 处理文件列表
                for item in result.get("InfoList", []):
                    item_path = f"{base_path}/{item['FileName']}" if base_path else item['FileName']
                    
                    if item["Type"] == 0:  # 文件
                        all_files.append({
                            "file_name": item_path,
                            "etag": item["Etag"],
                            "size": item["Size"],
                            "is_v2_etag": False  # 分享API返回的是标准MD5
                        })
                    elif item["Type"] == 1:  # 文件夹
                        # 递归处理子文件夹
                        process_folder(item["FileId"], item_path)
                
                # 检查是否有更多页面
                next_page = result.get("Next", -1)
                if next_page == -1:
                    break
        
        # 从根目录开始处理
        process_folder()
        return all_files

##########################123分享截至################################

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
            logger.debug(f"转换V2 ETag: {optimized_etag}")
            
            # 检查是否是有效的MD5格式（32位十六进制）
            if len(optimized_etag) == 32 and all(c in '0123456789abcdefABCDEF' for c in optimized_etag):
                logger.debug(f"ETag已经是有效的MD5格式: {optimized_etag}")
                return optimized_etag.lower()
            
            # 转换Base62到十六进制
            num = 0
            for char in optimized_etag:
                if char not in BASE62_CHARS:
                    logger.error(f"❌ ETag包含无效字符: {char}")
                    return optimized_etag
                num = num * 62 + BASE62_CHARS.index(char)
            
            # 转换为十六进制并确保32位
            hex_str = hex(num)[2:].lower()
            if len(hex_str) > 32:
                # 取后32位
                hex_str = hex_str[-32:]
                logger.warning(f"ETag转换后长度超过32位，截断为: {hex_str}")
            elif len(hex_str) < 32:
                # 前面补零
                hex_str = hex_str.zfill(32)
                logger.debug(f"ETag转换后不足32位，补零后: {hex_str}")
            
            # 验证是否为有效的MD5
            if len(hex_str) != 32 or not all(c in '0123456789abcdef' for c in hex_str):
                logger.error(f"❌ 转换后ETag格式无效: {hex_str}")
                return optimized_etag
            
            logger.debug(f"转换后ETag: {hex_str}")
            return hex_str
        except Exception as e:
            logger.error(f"❌ ETag转换失败: {str(e)}")
            return optimized_etag

class TelegramBotHandler:
    def __init__(self, token, pan_client, allowed_user_ids):
        self.token = token
        self.pan_client = pan_client
        self.allowed_user_ids = allowed_user_ids
        self.updater = Updater(token, use_context=True)
        self.dispatcher = self.updater.dispatcher
        self.start_time = pan_client.token_manager.start_time  # 记录启动时间
        
        # 注册处理程序
        self.dispatcher.add_handler(CommandHandler("start", self.start_command))
        self.dispatcher.add_handler(CommandHandler("export", self.export_command))
        self.dispatcher.add_handler(CommandHandler("sync_full", self.sync_full_command))
        self.dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, self.handle_text))
        self.dispatcher.add_handler(MessageHandler(Filters.document, self.handle_document))
        self.dispatcher.add_handler(CallbackQueryHandler(self.button_callback))
        
        # 设置菜单命令
        self.set_menu_commands()
    
    def set_menu_commands(self):
        """设置Telegram Bot菜单命令（带重试机制）"""
        commands = [
            BotCommand("start", "用户信息"),
            BotCommand("export", "导出秒传文件"),
            BotCommand("sync_full", "全量同步"),
        ]
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                self.updater.bot.set_my_commands(commands)
                logger.info("已设置Telegram Bot菜单命令")
                return
            except Exception as e:
                logger.error(f"设置菜单命令失败 (尝试 {attempt+1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(2)  # 等待2秒后重试
                else:
                    logger.error("无法设置菜单命令，将继续运行但不显示菜单")
    
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
                #logger.warning(f"用户 {user_id} 尝试访问但无权限")
                #update.message.reply_text("🚫 您没有权限使用此机器人")
                return
            return func(self, update, context, *args, **kwargs)
        return wrapper
    
    def auto_delete_message(self, context, chat_id, message_id, delay=3):
        """自动删除消息"""
        def delete():
            try:
                context.bot.delete_message(chat_id=chat_id, message_id=message_id)
                logger.debug(f"已自动删除消息: {message_id}")
            except Exception as e:
                if "message to delete not found" not in str(e).lower():
                    logger.error(f"删除消息失败: {str(e)}")
        
        # 使用线程延迟执行
        threading.Timer(delay, delete).start()
    
    def send_auto_delete_message(self, update, context, text, delay=3, chat_id=None):
        """发送自动删除的消息"""
        # 优先使用传入的 chat_id
        if chat_id is None:
            # 尝试从不同来源获取 chat_id
            if update and update.message:
                chat_id = update.message.chat_id
            elif update and update.callback_query and update.callback_query.message:
                chat_id = update.callback_query.message.chat_id
            elif context and hasattr(context, '_chat_id'):
                chat_id = context._chat_id
            else:
                logger.error("无法确定 chat_id，无法发送消息")
                return None
        
        message = context.bot.send_message(chat_id=chat_id, text=text)
        self.auto_delete_message(context, chat_id, message.message_id, delay)
        return message
    
    @admin_required
    def start_command(self, update: Update, context: CallbackContext):
        """处理/start命令，显示用户信息和机器人状态"""
        logger.info("收到/start命令")
        
        try:
            # 获取用户信息
            user_info = self.pan_client.get_user_info()
            if not user_info:
                self.send_auto_delete_message(update, context, "❌ 无法获取用户信息，请稍后再试")
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
                if size_bytes >= 1024 ** 4:  # TB
                    return f"{size_bytes / (1024 ** 4):.2f} TB"
                elif size_bytes >= 1024 ** 3:  # GB
                    return f"{size_bytes / (1024 ** 3):.2f} GB"
                elif size_bytes >= 1024 ** 2:  # MB
                    return f"{size_bytes / (1024 ** 2):.2f} MB"
                else:  # KB
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
                f"▫️ /sync_full 全量同步\n\n"
                f"⏱️ 已运行: {days}天{hours}小时{minutes}分{seconds}秒"
            )
            
            # 发送消息（不自动删除）
            update.message.reply_text(message)
            logger.info("已发送用户信息")
            
        except Exception as e:
            logger.error(f"处理/start命令出错: {str(e)}")
            self.send_auto_delete_message(update, context, "❌ 获取用户信息失败，请稍后再试")

    def search_database_by_name(self, name_pattern):
        """在数据库中进行模糊搜索"""
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                
                # 使用LIKE进行模糊匹配，支持部分匹配
                c.execute(
                    "SELECT * FROM directory_cache WHERE filename LIKE ? ORDER BY filename",
                    (f'%{name_pattern}%',)
                )
                
                rows = c.fetchall()
                logger.info(f"数据库中找到 {len(rows)} 个匹配项: '{name_pattern}'")
                
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"数据库搜索失败: {str(e)}")
            return []

    @admin_required
    def export_command(self, update: Update, context: CallbackContext):
        """处理/export命令，使用按钮选择文件夹"""
        logger.info("收到/export命令")
        
        # 获取命令参数
        search_query = " ".join(context.args) if context.args else ""
        
        if not search_query:
            self.send_auto_delete_message(update, context, "❌ 请指定要搜索的文件夹名称！格式: /export <文件夹名称>")
            return
        
        self.send_auto_delete_message(update, context, f"🔍 正在搜索文件夹: '{search_query}'...")
        
        try:
            # 在数据库中进行模糊搜索
            results = self.search_database_by_name(search_query)
            
            if not results:
                self.send_auto_delete_message(update, context, f"❌ 未找到包含 '{search_query}' 的文件夹")
                return
            
            # 保存结果到上下文
            context.user_data['export_search_results'] = results
            context.user_data['export_selected_indices'] = set()  # 存储用户选择的索引
            
            # 创建按钮键盘
            keyboard = []
            max_buttons = 40  # Telegram最多支持100个按钮，我们限制为40个
            
            # 添加文件夹选择按钮
            for i, result in enumerate(results[:max_buttons]):
                filename = result["filename"]
                # 截断过长的文件名
                display_name = filename if len(filename) <= 50 else f"{filename[:47]}..."
                keyboard.append([
                    InlineKeyboardButton(
                        f"{i+1}. {display_name}", 
                        callback_data=f"export_toggle_{i}"
                    )
                ])
            
            # 添加操作按钮
            action_buttons = [
                InlineKeyboardButton("✅ 全选", callback_data="export_select_all"),
                InlineKeyboardButton("❌ 取消全选", callback_data="export_deselect_all"),
                InlineKeyboardButton("🚀 开始导出", callback_data="export_confirm"),
                InlineKeyboardButton("❌ 取消操作", callback_data="export_cancel")
            ]
            
            # 分两行排列操作按钮
            keyboard.append(action_buttons[:2])
            keyboard.append(action_buttons[2:])
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            # 发送选择消息
            message = update.message.reply_text(
                f"✅ 找到 {len(results)} 个匹配项\n请选择要导出的文件夹:",
                reply_markup=reply_markup
            )
            
            # 保存消息ID用于后续更新
            context.user_data['export_message_id'] = message.message_id
            
            # 设置60秒超时定时器
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
        chat_id = query.message.chat_id
        message_id = query.message.message_id
        
        # 获取上下文数据
        results = context.user_data.get('export_search_results', [])
        selected_indices = context.user_data.get('export_selected_indices', set())
        
        if not results:
            query.edit_message_text("❌ 选择超时或结果已过期，请重新搜索")
            return
        
        # 处理不同类型的回调
        if data.startswith("export_toggle_"):
            # 切换选择状态
            try:
                index = int(data.split("_")[2])
                if index < len(results):
                    if index in selected_indices:
                        selected_indices.remove(index)
                    else:
                        selected_indices.add(index)
            except (ValueError, IndexError):
                pass
        
        elif data == "export_select_all":
            # 全选
            selected_indices = set(range(len(results)))
        
        elif data == "export_deselect_all":
            # 取消全选
            selected_indices = set()
        
        elif data == "export_confirm":
            # 确认导出
            self.process_export_selection(update, context, selected_indices)
            return
        
        elif data == "export_cancel":
            # 取消操作
            query.edit_message_text("❌ 导出操作已取消")
            self.cleanup_export_context(context.user_data)
            return
        
        # 更新上下文
        context.user_data['export_selected_indices'] = selected_indices
        
        # 更新消息
        self.update_export_message(update, context, results, selected_indices)
    
    def update_export_message(self, update: Update, context: CallbackContext, results, selected_indices):
        """更新导出选择消息"""
        query = update.callback_query
        selected_count = len(selected_indices)
        
        # 创建新键盘（保留原有结构）
        keyboard = []
        max_buttons = 40
        
        # 添加文件夹选择按钮（更新选中状态）
        for i, result in enumerate(results[:max_buttons]):
            filename = result["filename"]
            display_name = filename if len(filename) <= 50 else f"{filename[:47]}..."
            
            # 添加选中标记
            prefix = "✅ " if i in selected_indices else "⬜ "
            keyboard.append([
                InlineKeyboardButton(
                    f"{prefix}{i+1}. {display_name}", 
                    callback_data=f"export_toggle_{i}"
                )
            ])
        
        # 添加操作按钮
        action_buttons = [
            InlineKeyboardButton("✅ 全选", callback_data="export_select_all"),
            InlineKeyboardButton("❌ 取消全选", callback_data="export_deselect_all"),
            InlineKeyboardButton(f"🚀 导出({selected_count})", callback_data="export_confirm"),
            InlineKeyboardButton("❌ 取消", callback_data="export_cancel")
        ]
        
        # 分两行排列操作按钮
        keyboard.append(action_buttons[:2])
        keyboard.append(action_buttons[2:])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # 更新消息
        query.edit_message_text(
            text=f"✅ 找到 {len(results)} 个匹配项\n已选择 {selected_count} 个文件夹:",
            reply_markup=reply_markup
        )
    
    def export_timeout(self, context: CallbackContext):
        """导出选择超时处理"""
        job = context.job
        if not job or not job.context:
            logger.warning("超时任务缺少上下文数据")
            return
        
        job_context = job.context
        chat_id = job_context.get("chat_id")
        user_data = job_context.get("user_data", {})

        if not chat_id:
            logger.warning("超时任务缺少 chat_id")
            return
        
        # 获取消息ID
        if 'export_message_id' in user_data:
            message_id = user_data['export_message_id']

            try:
                # 编辑消息为超时提示
                self.updater.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=message_id,
                    text="⏱️ 操作超时，导出已自动取消"
                )
            except Exception as e:
                error_msg = str(e).lower()
                if "message to edit not found" in error_msg:
                    logger.debug("消息已被用户删除，无需处理")
                else:
                    logger.warning(f"编辑超时消息失败: {str(e)}")
        
        # 清理上下文
        self.cleanup_export_context(user_data)
    
    def cleanup_export_context(self, user_data: dict):
        """清理导出相关的上下文数据"""
        keys_to_remove = [
            'export_search_results', 
            'export_selected_indices', 
            'export_message_id'
        ]
        
        for key in keys_to_remove:
            if key in user_data:
                del user_data[key]
    
    def process_export_selection(self, update: Update, context: CallbackContext, selected_indices):
        """处理选择的导出任务"""
        query = update.callback_query
        
        # 获取保存的搜索结果
        results = context.user_data.get('export_search_results', [])
        if not results:
            query.edit_message_text("❌ 选择超时或结果已过期，请重新搜索")
            return
            
        # 检查是否选择了文件夹
        if not selected_indices:
            query.edit_message_text("❌ 请至少选择一个文件夹")
            return
            
        # 编辑消息显示处理中
        query.edit_message_text(f"⏳ 开始导出 {len(selected_indices)} 个文件夹...")
        
        # 取消超时任务
        if 'export_message_id' in context.user_data:
            message_id = context.user_data['export_message_id']
            job_name = f"export_timeout_{message_id}"
            
            # 查找并取消任务
            current_jobs = context.job_queue.get_jobs_by_name(job_name)
            for job in current_jobs:
                job.schedule_removal()
        
        # 处理选中的文件夹
        total = len(selected_indices)
        
        for i, idx in enumerate(selected_indices):
            # 获取选中的文件夹
            selected_folder = results[idx]
            folder_id = selected_folder["file_id"]
            folder_name = selected_folder["filename"]
            folder_path = selected_folder["full_path"]
            
            # 更新处理进度
            if i % 3 == 0:  # 每处理3个文件夹更新一次进度
                try:
                    query.edit_message_text(
                        f"⏳ 正在处理文件夹 [{i+1}/{total}]:\n"
                        f"├ 名称: {folder_name}\n"
                        f"└ 路径: {folder_path}"
                    )
                except:
                    pass
            
            # 获取文件夹内容
            files = self.pan_client.get_directory_files(folder_id, folder_name)
            
            if not files:
                logger.warning(f"文件夹为空: {folder_name}")
                continue
            
            # 创建JSON结构
            json_data = {
                "commonPath": folder_name,
                "usesBase62EtagsInExport": False,
                "files": [
                    {
                        "path": file_info["path"],
                        "etag": file_info["etag"],
                        "size": file_info["size"]
                    }
                    for file_info in files
                ]
            }
            
            # 清理文件夹名称
            clean_folder_name = re.sub(r'[\\/*?:"<>|]', "", folder_name)
            
            # 生成文件名
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_name = f"{clean_folder_name}_{timestamp}.json"
            
            # 保存为临时文件
            with open(file_name, "w", encoding="utf-8") as f:
                json.dump(json_data, f, ensure_ascii=False, indent=2)
            
            # 获取用户信息
            user_info = self.pan_client.get_user_info()
            nickname = user_info.get("nickname", "未知用户") if user_info else "未知用户"
            is_vip = user_info.get("vip", False) if user_info else False
            vip_status = "👑 尊享会员" if is_vip else "🔒 普通用户"
            
            # 创建分享信息
            caption = (
                f"✨来自：{nickname}的分享\n\n"
                f"📁 文件名: {clean_folder_name}\n"
                f"📝 文件数: {len(files)}\n\n"
                f"❤️ 123因您分享更完美！"
            )
            
            # 发送文件
            with open(file_name, "rb") as f:
                context.bot.send_document(
                    chat_id=query.message.chat_id,
                    document=f,
                    filename=file_name,
                    caption=caption
                )
            
            # 删除临时文件
            os.remove(file_name)
            logger.info(f"已发送导出文件: {file_name}")
        
        # 发送完成消息
        context.bot.send_message(
            chat_id=query.message.chat_id,
            text=f"✅ 导出完成！共处理 {total} 个文件夹"
        )
        
        # 清理上下文
        self.cleanup_export_context(context.user_data)
 
    @admin_required
    def handle_document(self, update: Update, context: CallbackContext):
        """处理文档消息（JSON文件）"""
        document = update.message.document
        user_id = update.message.from_user.id
        file_name = document.file_name
        
        # 检查是否是JSON文件
        if document.mime_type != "application/json" and not file_name.endswith(".json"):
            self.send_auto_delete_message(update, context, "❌ 请发送JSON格式的文件！")
            return
        
        logger.info(f"收到JSON文件: {file_name}")
        self.send_auto_delete_message(update, context, "📥 收到JSON文件，开始下载并解析...")
        
        # 下载文件
        file = context.bot.get_file(document.file_id)
        file_path = f"temp_{user_id}_{document.file_id}.json"
        file.download(file_path)
        
        # 读取并解析JSON
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                json_data = json.load(f)
            os.remove(file_path)
            
            logger.info(f"解析JSON文件: {file_name}")
            self.process_json_file(update, context, json_data)
        except Exception as e:
            logger.error(f"❌ 处理JSON文件出错: {str(e)}")
            self.send_auto_delete_message(update, context, f"❌ 处理JSON文件时出错: {str(e)}")
    
    @admin_required
    def process_fast_link(self, update: Update, context: CallbackContext, share_link):
        """处理秒传链接转存"""
        try:
            files = FastLinkProcessor.parse_share_link(share_link)
            if not files:
                logger.warning("无法解析秒传链接或链接中无有效文件信息")
                self.send_auto_delete_message(update, context, "❌ 无法解析秒传链接或链接中无有效文件信息")
                return
            
            logger.info(f"开始转存 {len(files)} 个文件...")
            self.send_auto_delete_message(update, context, f"✅ 解析成功！找到 {len(files)} 个文件，开始转存...")
            
            # 转存文件
            results = self.transfer_files(update, context, files)
            
            # 发送结果
            self.send_transfer_results(update, context, results)
            
        except Exception as e:
            logger.error(f"❌ 处理秒传链接出错: {str(e)}")
            self.send_auto_delete_message(update, context, f"❌ 处理秒传链接时出错: {str(e)}")
    
    @admin_required
    def process_json_file(self, update: Update, context: CallbackContext, json_data):
        """处理JSON文件转存"""
        try:
            if not isinstance(json_data, dict) or not json_data.get("files"):
                logger.warning("JSON格式无效，缺少files字段")
                self.send_auto_delete_message(update, context, "❌ JSON格式无效，缺少files字段")
                return
            
            common_path = json_data.get("commonPath", "").strip()
            if common_path.endswith('/'):
                common_path = common_path[:-1]
            
            files = []
            for file_info in json_data["files"]:
                file_path = file_info.get("path", "")
                if common_path:
                    file_path = f"{common_path}/{file_path}"
                
                files.append({
                    "etag": file_info.get("etag", ""),
                    "size": int(file_info.get("size", 0)),
                    "file_name": file_path,
                    "is_v2_etag": json_data.get("usesBase62EtagsInExport", False)
                })
            
            logger.info(f"开始转存 {len(files)} 个文件...")
            self.send_auto_delete_message(update, context, f"✅ 解析成功！找到 {len(files)} 个文件，开始转存...")
            
            # 转存文件
            results = self.transfer_files(update, context, files)
            
            # 发送结果
            self.send_transfer_results(update, context, results)
            
        except Exception as e:
            logger.error(f"❌ 处理JSON文件出错: {str(e)}")
            self.send_auto_delete_message(update, context, f"❌ 处理JSON文件时出错: {str(e)}")
    
    
    def transfer_files(self, update: Update, context: CallbackContext, files):
        """转存文件列表（带重试机制）"""
        logger.info(f"开始转存 {len(files)} 个文件...")
        results = []
        total_files = len(files)
        root_dir_id = self.pan_client.default_save_dir_id  # 使用配置的默认保存目录
        
        # 创建文件夹缓存
        folder_cache = {}
        
        for i, file_info in enumerate(files):
            file_path = file_info["file_name"]
            logger.info(f"处理文件 [{i+1}/{total_files}]: {file_path}")
            
            try:
                # 处理文件路径
                path_parts = file_path.split('/')
                file_name = path_parts.pop()
                parent_id = root_dir_id
                
                # 创建目录结构
                current_path = ""
                for part in path_parts:
                    if not part:
                        continue
                    
                    current_path = f"{current_path}/{part}" if current_path else part
                    cache_key = f"{parent_id}/{current_path}"
                    
                    # 检查缓存
                    if cache_key in folder_cache:
                        parent_id = folder_cache[cache_key]
                        continue
                    
                    # 创建新文件夹（带重试）
                    folder = self.pan_client.create_folder(parent_id, part)
                    if not folder:
                        logger.warning(f"⚠️ 创建文件夹失败: {part}，将使用根目录")
                        parent_id = root_dir_id
                    else:
                        folder_id = folder["FileId"]
                        folder_cache[cache_key] = folder_id
                        parent_id = folder_id
                
                # 处理ETag
                etag = file_info["etag"]
                if file_info.get("is_v2_etag", False):
                    etag = FastLinkProcessor.optimized_etag_to_hex(etag, True)
                
                # 秒传文件（带重试）
                result = self.pan_client.rapid_upload(
                    etag, 
                    file_info["size"],
                    file_name,
                    parent_id
                )
                
                if result:
                    results.append({
                        "success": True,
                        "file_name": file_path,
                        "file_id": result["FileId"]
                    })
                    logger.info(f"✅ 文件转存成功: {file_path}")
                else:
                    results.append({
                        "success": False,
                        "file_name": file_path,
                        "error": "秒传失败"
                    })
                    logger.error(f"❌ 文件转存失败: {file_path}")
            except Exception as e:
                logger.error(f"❌ 转存文件 {file_path} 出错: {str(e)}")
                results.append({
                    "success": False,
                    "file_name": file_path,
                    "error": str(e)
                })
        
        logger.info(f"文件转存完成，成功: {sum(1 for r in results if r['success'])}, 失败: {len(results) - sum(1 for r in results if r['success'])}")
        return results
    
    def send_transfer_results(self, update: Update, context: CallbackContext, results):
        """发送转存结果，包含失败文件详情（此消息不自动删除）"""
        success_count = sum(1 for r in results if r["success"])
        failed_count = len(results) - success_count
        
        # 构建基础结果文本
        result_text = (
            f"📊 转存完成！\n"
            f"✅ 成功: {success_count}\n"
            f"❌ 失败: {failed_count}\n"
            f"📁 保存目录: {DEFAULT_SAVE_DIR or '根目录'}"
        )
        
        # 添加失败文件详情
        if failed_count > 0:
            failed_files = []
            for result in results:
                if not result["success"]:
                    # 简化文件名显示
                    file_name = result["file_name"]
                    if len(file_name) > 50:
                        file_name = f"...{file_name[-47]}" if file_name else "未知文件"
                    
                    failed_files.append(f"• {file_name}: {result['error']}")
            
            result_text += "\n\n❌ 失败文件:\n" + "\n".join(failed_files[:10])  # 最多显示10个失败文件
            
            if failed_count > 10:
                result_text += f"\n...及其他 {failed_count - 10} 个失败文件"
        
        # 使用普通消息发送（不自动删除）
        chat_id = update.message.chat_id
        context.bot.send_message(chat_id=chat_id, text=result_text)
    
    @admin_required
    def sync_full_command(self, update: Update, context: CallbackContext):
        """处理/sync_full命令，全量同步目录缓存（带按钮确认）"""
        logger.info("收到/sync_full命令")
        
        # 创建按钮
        keyboard = [
            [
                InlineKeyboardButton("✅ 确认", callback_data='sync_full_confirm'),
                InlineKeyboardButton("❌ 取消", callback_data='sync_full_cancel')
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # 发送消息
        message = update.message.reply_text(
            "⚠️ 确认要执行全量同步吗？\n"
            "这将更新整个媒体库的目录缓存，可能需要较长时间。",
            reply_markup=reply_markup
        )
        
        # 保存消息ID，用于后续删除
        context.user_data['confirmation_message_id'] = message.message_id

    def button_callback(self, update: Update, context: CallbackContext):
        """处理按钮回调"""
        query = update.callback_query
        query.answer()
        
        data = query.data
        
        # 根据回调类型分发处理
        if data.startswith("export_"):
            self.export_choice_callback(update, context)
        elif data.startswith("sync_full_"):
            # 原有的全量同步处理
            chat_id = query.message.chat_id
            message_id = query.message.message_id
            
            if data == 'sync_full_confirm':
                try:
                    context.bot.delete_message(chat_id=chat_id, message_id=message_id)
                except Exception as e:
                    logger.error(f"删除消息失败: {str(e)}")
                self.execute_full_sync(update, context)
            elif data == 'sync_full_cancel':
                try:
                    context.bot.delete_message(chat_id=chat_id, message_id=message_id)
                except Exception as e:
                    logger.error(f"删除消息失败: {str(e)}")
                context.bot.send_message(chat_id=chat_id, text="❌ 全量同步已取消")

    def execute_full_sync(self, update: Update, context: CallbackContext):
        """执行全量同步"""
        # 尝试从上下文获取 chat_id
        chat_id = getattr(context, '_chat_id', None)
        
        self.send_auto_delete_message(
            update, context, 
            "🔄 正在执行全量同步，这可能需要一些时间...",
            chat_id=chat_id
        )
        
        try:
            start_time = time.time()
            update_count = self.pan_client.full_sync_directory_cache()
            elapsed = time.time() - start_time
            
            self.send_auto_delete_message(
                update, context, 
                f"✅ 全量同步完成！\n"
                f"├ 更新目录: {update_count} 个\n"
                f"├ 总缓存数: {len(self.pan_client.directory_cache)}\n"
                f"└ 耗时: {elapsed:.2f}秒",
                chat_id=chat_id
            )
        except Exception as e:
            logger.error(f"全量同步失败: {str(e)}")
            self.send_auto_delete_message(
                update, context, 
                f"❌ 全量同步失败: {str(e)}",
                chat_id=chat_id
            )
            
        # 清理上下文
        if hasattr(context, '_chat_id'):
            del context._chat_id

#########################123分享开始################################

    def parse_share_url(self, share_url):
        """解析分享链接，提取ShareKey和提取码（提取码可选）"""
        try:
            # 使用更健壮的正则表达式匹配分享链接
            pattern = r'(https?://(?:[a-zA-Z0-9-]+\.)*123[a-zA-Z0-9-]*\.[a-z]{2,6}/s/([a-zA-Z0-9\-_]+))(?:[\s\S]*?(?:提取码|密码|code)[\s:：=]*(\w{4}))?'
            match = re.search(pattern, share_url, re.IGNORECASE)

            if match:
                # 完整URL
                full_url = match.group(1)
                # ShareKey
                share_key = match.group(2)
                # 提取码（可选）
                password = match.group(3) if match.group(3) else ""
                # 尝试从URL查询参数中获取提取码（优先级更高）
                parsed = urlparse(full_url)
                query_params = parse_qs(parsed.query)
                if 'pwd' in query_params:
                    password = query_params['pwd'][0]
                logger.debug(f"解析分享链接: URL={full_url}, ShareKey={share_key}, Password={password}")
                return share_key, password
            
            logger.warning(f"无法解析分享链接: {share_url}")
            return None, None
        except Exception as e:
            logger.error(f"解析分享链接失败: {str(e)}")
            return None, None
        
    def process_share_link(self, update: Update, context: CallbackContext, share_url):
        """处理123云盘分享链接转存"""
        # 首先解析分享链接
        parsed = self.parse_share_url(share_url)
        if not parsed:
            self.send_auto_delete_message(update, context, "❌ 无法解析分享链接")
            return
        
        # 解包解析结果
        share_key, password = parsed
        
        logger.info(f"解析分享链接: ShareKey={share_key}, Password={password}")
        self.send_auto_delete_message(update, context, f"🔍 解析成功! ShareKey: {share_key}...")
        
        # 发送初始进度消息
        chat_id = update.message.chat_id
        progress_msg = context.bot.send_message(
            chat_id=chat_id,
            text=f"⏳ 正在获取分享内容，请稍候...\nShareKey: {share_key}"
        )
        
        try:
            # 获取分享中的所有文件
            files = self.pan_client.get_all_share_files(share_key, password)
            
            if not files:
                context.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=progress_msg.message_id,
                    text="❌ 分享中没有文件或获取失败"
                )
                return
            
            # 更新进度消息
            context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=progress_msg.message_id,
                text=f"✅ 成功获取 {len(files)} 个文件，开始转存..."
            )
            
            # 转存文件
            results = self.transfer_files(update, context, files)
            
            # 发送结果
            self.send_transfer_results(update, context, results)
            
        except Exception as e:
            logger.error(f"处理分享链接出错: {str(e)}")
            context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=progress_msg.message_id,
                text=f"❌ 处理分享链接时出错: {str(e)}"
            )

#########################123分享截至################################
    @admin_required
    def handle_text(self, update: Update, context: CallbackContext):
        """处理文本消息（秒传链接）"""
        text = update.message.text.strip()
        
        # 检查是否是秒传链接
        if (text.startswith(LEGACY_FOLDER_LINK_PREFIX_V1) or 
            text.startswith(LEGACY_FOLDER_LINK_PREFIX_V2) or 
            text.startswith(COMMON_PATH_LINK_PREFIX_V1) or 
            text.startswith(COMMON_PATH_LINK_PREFIX_V2) or
            ('#' in text and '$' in text)):  # 更宽松的匹配
            logger.info(f"收到秒传链接: {text[:50]}...")
            self.send_auto_delete_message(update, context, "🔍 检测到秒传链接，开始解析...")
            self.process_fast_link(update, context, text)

        # 检查是否是123云盘分享链接
        elif re.search(r'123[a-zA-Z0-9-]*\.[a-z]{2,6}/(s|b)/[a-zA-Z0-9\-_]+', text, re.IGNORECASE):
            logger.info(f"收到123云盘分享链接: {text}")
            self.send_auto_delete_message(update, context, "🔍 检测到123云盘分享链接，开始解析...")
            self.process_share_link(update, context, text)

def main():
    # 从环境变量读取配置
    BOT_TOKEN = os.getenv("TG_BOT_TOKEN","")
    CLIENT_ID = os.getenv("PAN_CLIENT_ID","")
    CLIENT_SECRET = os.getenv("PAN_CLIENT_SECRET","")
    ADMIN_USER_IDS = [int(id.strip()) for id in os.getenv("TG_ADMIN_USER_IDS", "").split(",") if id.strip()]
    
    # 检查配置是否完整
    if not BOT_TOKEN:
        logger.error("❌ 环境变量 TG_BOT_TOKEN 未设置")
        return
    
    if not CLIENT_ID:
        logger.error("❌ 环境变量 PAN_CLIENT_ID 未设置")
        return
    
    if not CLIENT_SECRET:
        logger.error("❌ 环境变量 PAN_CLIENT_SECRET 未设置")
        return
    
    if not ADMIN_USER_IDS:
        logger.warning("⚠️ 环境变量 TG_ADMIN_USER_IDS 未设置或为空，机器人将对所有用户开放")
    
    # 记录配置信息
    #logger.info(f"转存目录: {DEFAULT_SAVE_DIR or '根目录'}")
    #logger.info(f"导出基目录: {', '.join(EXPORT_BASE_DIRS) if EXPORT_BASE_DIRS else '根目录'}")
    #logger.info(f"搜索最大深度: {SEARCH_MAX_DEPTH}层")
    
    logger.info("初始化123云盘客户端...")
    pan_client = Pan123Client(CLIENT_ID, CLIENT_SECRET)
    
    # 确保Token已加载或获取
    if not pan_client.token_manager.access_token:
        logger.error("❌ 无法获取有效的Token，请检查凭证")
        return
    
    logger.info("初始化Telegram机器人...")
    bot_handler = TelegramBotHandler(BOT_TOKEN, pan_client, ADMIN_USER_IDS)
    
    # 启动机器人
    logger.info("机器人启动中...")
    bot_handler.start()

if __name__ == "__main__":
    main()
