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
from telegram import Update, BotCommand
from telegram.ext import (
    Updater, 
    MessageHandler, 
    Filters, 
    CallbackContext, 
    CommandHandler
)
from functools import wraps
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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
EXPORT_BASE_DIR = os.getenv("EXPORT_BASE_DIR", "").strip()    # 导出操作的基目录
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
        self.export_base_dir_id = 0   # 根目录
        
        # 设置默认保存目录
        if DEFAULT_SAVE_DIR:
            self.default_save_dir_id = self.get_or_create_directory(DEFAULT_SAVE_DIR)
            logger.info(f"默认保存目录已设置: '{DEFAULT_SAVE_DIR}' (ID: {self.default_save_dir_id})")
        
        # 设置导出基目录
        if EXPORT_BASE_DIR:
            self.export_base_dir_id = self.get_or_create_directory(EXPORT_BASE_DIR)
            logger.info(f"导出基目录已设置: '{EXPORT_BASE_DIR}' (ID: {self.export_base_dir_id})")
        
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
                c.execute("SELECT * FROM directory_cache WHERE base_dir_id = ?", (self.export_base_dir_id,))
                rows = c.fetchall()
                
                for row in rows:
                    file_id = row["file_id"]
                    self.directory_cache[file_id] = dict(row)
                
                logger.info(f"已加载 {len(rows)} 个目录缓存 (导出基目录ID: {self.export_base_dir_id})")
        except Exception as e:
            logger.error(f"加载目录缓存失败: {str(e)}")
    
    def update_directory_cache(self, file_id, filename, parent_id, full_path):
        """更新目录缓存"""
        try:
            # 检查是否已存在
            if file_id in self.directory_cache:
                existing = self.directory_cache[file_id]
                if (existing["filename"] == filename and 
                    existing["parent_id"] == parent_id and 
                    existing["full_path"] == full_path):
                    return False  # 无变化，无需更新
            
            # 更新内存缓存
            cache_entry = {
                "file_id": file_id,
                "filename": filename,
                "parent_id": parent_id,
                "full_path": full_path,
                "base_dir_id": self.export_base_dir_id
            }
            self.directory_cache[file_id] = cache_entry
            
            # 更新数据库
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                # 使用INSERT OR REPLACE确保更新
                c.execute('''INSERT OR REPLACE INTO directory_cache 
                            (file_id, filename, parent_id, full_path, base_dir_id) 
                            VALUES (?,?,?,?,?)''',
                          (file_id, filename, parent_id, full_path, self.export_base_dir_id))
                conn.commit()
            
            logger.info(f"更新目录缓存: {filename} (ID: {file_id}, 路径: {full_path})")
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
            update_count = self.sync_directory(self.export_base_dir_id, EXPORT_BASE_DIR or "根目录")
            logger.info(f"全量同步完成，更新 {update_count} 个目录")
            return update_count
        except Exception as e:
            logger.error(f"全量同步失败: {str(e)}")
            return 0
    
    def sync_directory_by_path(self, path):
        """
        同步指定路径的目录
        :param path: 相对于导出基目录的路径（如"电视剧/国产剧"）
        :return: 更新的目录数量
        """
        logger.info(f"开始同步目录路径: '{path}'")
        
        # 分解路径
        parts = [p for p in path.split('/') if p]
        if not parts:
            logger.warning("路径为空，将同步整个基目录")
            return self.full_sync_directory_cache()
        
        # 从基目录开始查找
        parent_id = self.export_base_dir_id
        current_path = EXPORT_BASE_DIR or "根目录"
        found = True
        
        try:
            # 逐级查找目录
            for part in parts:
                # 先在缓存中查找
                cached = self.search_in_cache(part, parent_id)
                if cached:
                    parent_id = cached[0]["file_id"]
                    current_path = cached[0]["full_path"]
                    logger.debug(f"在缓存中找到目录: {part} (ID: {parent_id})")
                    continue
                
                # 缓存中没有，通过API查找
                folder_info = self.search_folder(part, parent_id)
                if folder_info:
                    parent_id = folder_info["fileId"]
                    current_path = f"{current_path}/{part}" if current_path else part
                    logger.info(f"通过API找到目录: {part} (ID: {parent_id})")
                    
                    # 添加到缓存
                    self.update_directory_cache(
                        parent_id,
                        part,
                        folder_info.get("parent_id", 0),
                        current_path
                    )
                else:
                    logger.error(f"找不到目录: {part} (父ID: {parent_id})")
                    found = False
                    break
            
            if not found:
                return 0
            
            # 同步找到的目录
            logger.info(f"开始同步目录: '{current_path}' (ID: {parent_id})")
            count = self.sync_directory(parent_id, current_path)
            logger.info(f"目录同步完成: '{path}', 更新 {count} 个目录")
            return count
        except Exception as e:
            logger.error(f"目录同步失败: {str(e)}")
            return 0
    
    def sync_directory(self, directory_id, current_path, current_depth=0):
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
                            item_path
                        )
                        if updated:
                            update_count += 1
                            logger.info(f"更新目录缓存: {item['filename']} (ID: {item['fileId']}, 路径: {item_path})")
                        
                        # 递归同步子目录（在深度限制内）
                        if current_depth < self.search_max_depth:
                            update_count += self.sync_directory(
                                item["fileId"],
                                item_path,
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
                            item_path
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
        
        if is_common_path_format:
            delimiter_pos = share_link.find(COMMON_PATH_DELIMITER)
            if delimiter_pos > -1:
                common_base_path = share_link[:delimiter_pos]
                share_link = share_link[delimiter_pos + 1:]
        
        if not is_common_path_format:
            if share_link.startswith(LEGACY_FOLDER_LINK_PREFIX_V2):
                is_v2_etag_format = True
                share_link = share_link[len(LEGACY_FOLDER_LINK_PREFIX_V2):]
            elif share_link.startswith(LEGACY_FOLDER_LINK_PREFIX_V1):
                share_link = share_link[len(LEGACY_FOLDER_LINK_PREFIX_V1):]
        
        files = []
        for s_link in share_link.split('$'):
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
            num = 0
            for char in optimized_etag:
                num = num * 62 + BASE62_CHARS.index(char)
            
            hex_str = hex(num)[2:].lower()
            
            if len(hex_str) < 32:
                hex_str = hex_str.zfill(32)
            
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
        self.dispatcher.add_handler(CommandHandler("sync", self.sync_command))
        self.dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, self.handle_text))
        self.dispatcher.add_handler(MessageHandler(Filters.document, self.handle_document))
        
        # 设置菜单命令
        self.set_menu_commands()
    
    def set_menu_commands(self):
        """设置Telegram Bot菜单命令（带重试机制）"""
        commands = [
            BotCommand("start", "用户信息"),
            BotCommand("export", "导出秒传文件"),
            BotCommand("sync", "同步指定目录"),
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
    
    def auto_delete_message(self, context, chat_id, message_id, delay=10):
        """自动删除消息"""
        def delete():
            try:
                context.bot.delete_message(chat_id=chat_id, message_id=message_id)
                logger.debug(f"已自动删除消息: {message_id}")
            except Exception as e:
                logger.error(f"删除消息失败: {str(e)}")
        
        # 使用线程延迟执行
        threading.Timer(delay, delete).start()
    
    def send_auto_delete_message(self, update, context, text, delay=10, chat_id=None):
        """发送自动删除的消息"""
        if chat_id is None:
            chat_id = update.message.chat_id
        
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
                f"├ 导出目录: {EXPORT_BASE_DIR or '根目录'}\n"
                f"├ 搜索深度: {SEARCH_MAX_DEPTH}层\n"
                f"└ 数据缓存: {len(self.pan_client.directory_cache)}\n\n"
                f"🤖 机器人控制中心\n"
                f"▫️ /export 琅琊榜\n"
                f"▫️ /sync 电视剧/国产剧\n\n"
                f"⏱️ 已运行: {days}天{hours}小时{minutes}分{seconds}秒"
            )
            
            # 发送消息（不自动删除）
            update.message.reply_text(message)
            logger.info("已发送用户信息")
            
        except Exception as e:
            logger.error(f"处理/start命令出错: {str(e)}")
            self.send_auto_delete_message(update, context, "❌ 获取用户信息失败，请稍后再试")
    
    @admin_required
    def export_command(self, update: Update, context: CallbackContext):
        """处理/export命令，模糊匹配文件夹并提供选择"""
        logger.info("收到/export命令")
        
        # 获取命令参数（合并所有参数为搜索关键词）
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
            
            # 格式化结果并保存到上下文
            formatted_results = []
            response_lines = []
            
            # 构建响应消息
            response_lines.append(f"✅ 找到 {len(results)} 个匹配项:\n")
            
            for i, result in enumerate(results, start=1):
                file_id = result["file_id"]
                filename = result["filename"]
                full_path = result["full_path"]
                
                formatted_results.append({
                    "file_id": file_id,
                    "filename": filename,
                    "full_path": full_path
                })
                
                # 添加结果到响应消息
                response_lines.append(
                    f"{i}. 📁 名称: {filename}\n"
                    f"   🔢 ID: {file_id}\n"
                    f"   📂 路径: {full_path}\n"
                )
            
            # 添加选择提示
            response_lines.append("\n请回复序号选择要导出的文件夹")
            
            # 将所有结果合并为一条消息发送
            response_message = "\n".join(response_lines)
            update.message.reply_text(response_message)
            
            # 保存结果到上下文并提示用户选择
            context.user_data['export_search_results'] = formatted_results
            context.user_data['waiting_for_export_choice'] = True
            
        except Exception as e:
            logger.error(f"搜索文件夹失败: {str(e)}")
            self.send_auto_delete_message(update, context, f"❌ 搜索失败: {str(e)}")
    
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
    
    def handle_export_choice(self, update: Update, context: CallbackContext, choice: str):
        """处理用户选择的导出序号"""
        try:
            # 获取保存的搜索结果
            results = context.user_data.get('export_search_results', [])
            if not results:
                self.send_auto_delete_message(update, context, "❌ 选择超时或结果已过期，请重新搜索")
                return
                
            # 验证用户输入
            try:
                choice_index = int(choice) - 1
                if choice_index < 0 or choice_index >= len(results):
                    self.send_auto_delete_message(update, context, "❌ 序号无效，请输入列表中的序号")
                    return
            except ValueError:
                self.send_auto_delete_message(update, context, "❌ 请输入有效数字序号")
                return
                
            # 获取选中的文件夹
            selected_folder = results[choice_index]
            folder_id = selected_folder["file_id"]
            folder_name = selected_folder["filename"]
            folder_path = selected_folder["full_path"]
            
            # 清除上下文状态
            context.user_data.pop('export_search_results', None)
            context.user_data.pop('waiting_for_export_choice', None)
            
            # 开始导出
            self.send_auto_delete_message(
                update, context,
                f"✅ 已选择: {folder_name}\n"
                f"├ ID: {folder_id}\n"
                f"└ 路径: {folder_path}\n"
                f"开始导出内容..."
            )
            
            # 获取文件夹内容
            files = self.pan_client.get_directory_files(folder_id, folder_name)
            
            if not files:
                self.send_auto_delete_message(update, context, "⚠️ 该文件夹为空")
                return
            
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
            file_name = f"{clean_folder_name}.json"
            
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
                    chat_id=update.message.chat_id,
                    document=f,
                    filename=file_name,
                    caption=caption
                )
            
            # 删除临时文件
            os.remove(file_name)
            logger.info(f"已发送导出文件: {file_name}")
            
        except Exception as e:
            logger.error(f"导出文件夹失败: {str(e)}")
            self.send_auto_delete_message(update, context, f"❌ 导出失败: {str(e)}")
    
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
                    if folder:
                        folder_id = folder["FileId"]
                        folder_cache[cache_key] = folder_id
                        parent_id = folder_id
                    else:
                        logger.warning(f"⚠️ 创建文件夹失败: {part}，将使用根目录")
                        parent_id = root_dir_id
                
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
        """发送转存结果，包含失败文件详情"""
        success_count = sum(1 for r in results if r["success"])
        failed_count = len(results) - success_count
        
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
                        file_name = f"...{file_name[-47]}"
                    
                    failed_files.append(f"• {file_name}: {result['error']}")
            
            result_text += "\n\n❌ 失败文件:\n" + "\n".join(failed_files[:10])  # 最多显示10个失败文件
            
            if failed_count > 10:
                result_text += f"\n...及其他 {failed_count - 10} 个失败文件"
        
        # 发送并自动删除
        self.send_auto_delete_message(update, context, result_text)

    @admin_required
    def sync_full_command(self, update: Update, context: CallbackContext):
        """处理/sync_full命令，全量同步目录缓存（带文字确认）"""
        logger.info("收到/sync_full命令")
        
        # 发送确认消息
        message = update.message.reply_text(
            "⚠️ 确认要执行全量同步吗？\n"
            "这将更新整个媒体库的目录缓存，可能需要较长时间。\n\n"
            "请回复 '确认' 开始同步，或 '取消' 中止操作。\n"
            "⏱️ 60秒内未回复将自动取消。"
        )
        
        # 设置上下文状态
        context.user_data['waiting_sync_confirmation'] = True
        context.user_data['sync_type'] = 'full'
        context.user_data['confirmation_message_id'] = message.message_id
        
        # 设置60秒后自动取消
        context.job_queue.run_once(
            self.cancel_sync_confirmation, 
            60, 
            context={
                'chat_id': update.message.chat_id,
                'message_id': message.message_id
            }
        )
    
    @admin_required
    def sync_command(self, update: Update, context: CallbackContext):
        """处理/sync命令，同步指定目录（带文字确认）"""
        logger.info("收到/sync命令")
        
        # 获取命令参数
        path = " ".join(context.args) if context.args else ""
        
        if not path:
            self.send_auto_delete_message(update, context, "❌ 请指定要同步的目录路径！格式: /sync <目录路径>")
            return
        
        # 发送确认消息
        message = update.message.reply_text(
            f"⚠️ 确认要同步目录吗？\n"
            f"路径: '{path}'\n\n"
            f"请回复 '确认' 开始同步，或 '取消' 中止操作。\n"
            f"⏱️ 60秒内未回复将自动取消。"
        )
        
        # 设置上下文状态
        context.user_data['waiting_sync_confirmation'] = True
        context.user_data['sync_type'] = 'partial'
        context.user_data['sync_path'] = path
        context.user_data['confirmation_message_id'] = message.message_id
        
        # 设置60秒后自动取消
        context.job_queue.run_once(
            self.cancel_sync_confirmation, 
            60, 
            context={
                'chat_id': update.message.chat_id,
                'message_id': message.message_id
            }
        )
    
    def cancel_sync_confirmation(self, context: CallbackContext):
        """60秒后自动取消同步确认"""
        job = context.job
        context_data = job.context
        
        chat_id = context_data['chat_id']
        message_id = context_data['message_id']
        
        try:
            # 删除确认消息
            context.bot.delete_message(chat_id=chat_id, message_id=message_id)
            
            # 发送取消通知
            context.bot.send_message(
                chat_id=chat_id,
                text="⏱️ 同步操作已自动取消（60秒未确认）"
            )
        except Exception as e:
            logger.error(f"取消确认时出错: {str(e)}")
    
    def handle_text(self, update: Update, context: CallbackContext):
        """处理文本消息（秒传链接或导出选择或同步确认）"""
        text = update.message.text.strip().lower()
        
        # 检查是否是导出选择
        if context.user_data.get('waiting_for_export_choice', False):
            logger.info(f"收到导出选择: {text}")
            self.handle_export_choice(update, context, text)
            return
        
        # 检查是否是同步确认
        if context.user_data.get('waiting_sync_confirmation', False):
            if text == '确认':
                self.process_sync_confirmation(update, context)
            elif text == '取消':
                self.cancel_sync_operation(update, context)
            else:
                self.send_auto_delete_message(
                    update, context,
                    "❌ 无效回复，请回复 '确认' 或 '取消'",
                    delay=5
                )
            return
        
        # 检查是否是秒传链接
        if any(prefix in text for prefix in [
            LEGACY_FOLDER_LINK_PREFIX_V1,
            LEGACY_FOLDER_LINK_PREFIX_V2,
            COMMON_PATH_LINK_PREFIX_V1,
            COMMON_PATH_LINK_PREFIX_V2
        ]):
            logger.info(f"收到秒传链接: {text[:50]}...")
            self.send_auto_delete_message(update, context, "🔍 检测到秒传链接，开始解析...")
            self.process_fast_link(update, context, text)
    
    def process_sync_confirmation(self, update: Update, context: CallbackContext):
        """处理同步确认"""
        # 清除状态
        context.user_data.pop('waiting_sync_confirmation', None)
        message_id = context.user_data.pop('confirmation_message_id', None)
        
        # 删除确认消息
        if message_id:
            try:
                context.bot.delete_message(
                    chat_id=update.message.chat_id,
                    message_id=message_id
                )
            except:
                pass
        
        # 获取同步类型
        sync_type = context.user_data.get('sync_type')
        path = context.user_data.get('sync_path', '')
        
        # 执行同步操作
        if sync_type == 'full':
            self.execute_full_sync(update, context)
        elif sync_type == 'partial':
            self.execute_partial_sync(update, context, path)
    
    def cancel_sync_operation(self, update: Update, context: CallbackContext):
        """取消同步操作"""
        # 清除状态
        context.user_data.pop('waiting_sync_confirmation', None)
        message_id = context.user_data.pop('confirmation_message_id', None)
        
        # 删除确认消息
        if message_id:
            try:
                context.bot.delete_message(
                    chat_id=update.message.chat_id,
                    message_id=message_id
                )
            except:
                pass
        
        # 发送取消通知
        self.send_auto_delete_message(
            update, context,
            "❌ 同步操作已取消",
            delay=10
        )
    
    def execute_full_sync(self, update: Update, context: CallbackContext):
        """执行全量同步"""
        self.send_auto_delete_message(
            update, context, 
            "🔄 正在执行全量同步，这可能需要一些时间..."
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
                f"└ 耗时: {elapsed:.2f}秒"
            )
        except Exception as e:
            logger.error(f"全量同步失败: {str(e)}")
            self.send_auto_delete_message(
                update, context, 
                f"❌ 全量同步失败: {str(e)}"
            )
    
    def execute_partial_sync(self, update: Update, context: CallbackContext, path: str):
        """执行目录同步"""
        self.send_auto_delete_message(
            update, context, 
            f"🔄 正在同步目录: '{path}'..."
        )
        
        try:
            start_time = time.time()
            update_count = self.pan_client.sync_directory_by_path(path)
            elapsed = time.time() - start_time
            
            if update_count == 0:
                self.send_auto_delete_message(
                    update, context, 
                    f"⚠️ 目录同步完成，但未更新任何目录\n"
                    f"└ 耗时: {elapsed:.2f}秒\n"
                    f"可能原因: 目录已是最新状态或路径不存在"
                )
            else:
                self.send_auto_delete_message(
                    update, context, 
                    f"✅ 目录同步完成！\n"
                    f"├ 更新目录: {update_count} 个\n"
                    f"├ 总缓存数: {len(self.pan_client.directory_cache)}\n"
                    f"└ 耗时: {elapsed:.2f}秒"
                )
        except Exception as e:
            logger.error(f"目录同步失败: {str(e)}")
            self.send_auto_delete_message(
                update, context, 
                f"❌ 目录同步失败: {str(e)}"
            )

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
    #logger.info(f"导出基目录: {EXPORT_BASE_DIR or '根目录'}")
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
