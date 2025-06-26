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
import concurrent.futures
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
from p115client import P115Client
from p115 import P115Client, P115ShareFileSystem, P115FileSystem
from p115client.tool.iterdir import iter_files, get_id_to_path
from p115client.tool.download import iter_url_batches

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
logging.getLogger("p115client").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.ERROR)
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
    "DIRECTORY_CREATE": "/upload/v1/file/mkdir"
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

# 115网盘配置
DEFAULT_SOURCE_PATH = os.getenv("DEFAULT_SOURCE_PATH", "我的接收")
P115_COOKIE = os.getenv("P115_COOKIE", "")
MOBILE_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
SHARE_LINK_PATTERN = re.compile(
    r'(https?://(?:115\.com|115cdn\.com)/s/\w+)(?:\?password=\w{4})?[^\s]*',
    re.IGNORECASE
)
MAX_SUBMIT_RETRIES = 5  # 115任务提交最大重试次数
RETRY_DELAY = 10       # 115重试延迟时间(秒)
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

def format_duration(seconds):
    """格式化时间间隔"""
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"

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


class Pan115Transfer:
    """115网盘转存迁移类"""
    def __init__(self, pan_client, access_token):
        self.pan_client = pan_client
        self.access_token = access_token
        self.created_dirs = {}
        self.target_root_id = self.create_123_directory(DEFAULT_SAVE_DIR)
        self.transfer_stats = {
            "total_files": 0,
            "filtered_files": 0,
            "submitted_files": 0,
            "success_files": 0,
            "failed_files": 0,
            "start_time": time.time(),
            "total_size": 0,
            "filtered_size": 0
        }
        
        # 初始化115客户端
        self.client_115 = self.init_115_client()
        self.default_source_dir_id = self.find_115_directory_id(DEFAULT_SOURCE_PATH)
    
    def init_115_client(self):
        """初始化115网盘客户端"""
        logger.info("初始化115网盘客户端...")
        if not P115_COOKIE:
            raise ValueError("未设置P115_COOKIE环境变量")

        client = P115Client(cookies=P115_COOKIE)
        try:
            user_info = client.user_info(headers={"User-Agent": MOBILE_UA})
            logger.info(f"115登录成功!")
            return client
        except Exception as e:
            logger.error(f"115登录失败: {str(e)}")
            raise
    
    def find_115_directory_id(self, path):
        """查找115目录ID"""
        if not path or path == "/":
            return 0
            
        try:
            dir_id = get_id_to_path(
                client=self.client_115,
                path=path,
                parent_id=0,
                ensure_file=False,
                app='web',
            )
            return dir_id
        except Exception as e:
            logger.error(f"获取目录ID失败: {path} - {str(e)}")
            return None
    
    def extract_share_info(self, text):
        """从文本中提取115分享链接和密码"""
        matches = re.finditer(SHARE_LINK_PATTERN, text)
        share_links = []
        
        for match in matches:
            url = match.group(0)
            parsed = urlparse(url)
            password = parse_qs(parsed.query).get('password', [''])[0]
            
            if password and len(password) == 4:
                share_links.append((url, password))
            else:
                share_links.append((url, ''))
        
        return share_links
    
    def save_share_to_115(self, text, target_path=DEFAULT_SOURCE_PATH):
        """将分享链接中的文件保存到115网盘的中转站"""
        target_dir_id = self.find_115_directory_id(target_path)
        if target_dir_id is None:
            logger.error(f"目标目录不存在: {target_path}")
            return False
        
        share_links = self.extract_share_info(text)
        if not share_links:
            logger.error("无法解析分享链接")
            return False
        
        results = []
        for url, password in share_links:
            logger.info(f"处理分享链接: {url}")
            if password:
                logger.info(f"使用提取码: {password}")
            
            try:
                parsed = urlparse(url)
                path_parts = parsed.path.split('/')
                if len(path_parts) < 3 or path_parts[1] != 's':
                    logger.error(f"❌ 无效的分享链接格式: {url}")
                    results.append(False)
                    continue
                
                share_code = path_parts[2]
                
                share_fs = P115ShareFileSystem(
                    client=self.client_115, 
                    share_code=share_code,
                    receive_code=password,
                )
                
                resp = share_fs.receive(0, target_dir_id)
                
                if resp.get("state") is True:
                    logger.info("✅ 分享内容转存成功!")
                    results.append(True)
                else:
                    error_msg = resp.get("error", "未知错误")
                    logger.error(f"❌ 转存失败: {error_msg}")
                    results.append(False)
                    
            except Exception as e:
                logger.error(f"❌ 保存分享文件失败: {str(e)}")
                results.append(False)
        
        return all(results)
    
    def scan_115_directory(self, path):
        """扫描115目录获取文件列表"""
        logger.info(f"扫描目录: {path}...")
        files = []
        dir_id = self.find_115_directory_id(path)
        if dir_id is None:
            logger.error(f"目录ID未找到: {path}")
            return []
            
        try:
            for item in iter_files(
                client=self.client_115,
                cid=dir_id,
                type=99,  # 仅文件
                cur=0,    # 递归子目录
                with_path=True,
                escape=False,
            ):
                try:
                    if "name" not in item or "path" not in item:
                        continue
                    
                    # 记录扫描到的文件
                    self.transfer_stats["total_files"] += 1
                    self.transfer_stats["total_size"] += item.get("size", 0)
                    
                    # 检查文件扩展名
                    file_ext = os.path.splitext(item["name"])[1].lower()
                    if file_ext not in ALLOWED_VIDEO_EXTENSIONS + ALLOWED_SUB_EXTENSIONS:
                        self.transfer_stats["filtered_files"] += 1
                        self.transfer_stats["filtered_size"] += item.get("size", 0)
                        continue
                        
                    # 规范化路径比较
                    norm_path = os.path.normpath(path)
                    item_path = os.path.normpath(item["path"].lstrip('/'))
                    
                    # 处理相对路径
                    if item_path == norm_path:
                        rel_path = ""
                    elif item_path.startswith(norm_path + os.sep):
                        rel_path = item_path[len(norm_path)+1:]
                    else:
                        rel_path = item_path
                    
                    parent_id = item.get("cid", dir_id)
                    
                    files.append({
                        "name": item["name"],
                        "path": os.path.dirname(rel_path) if rel_path else "",
                        "size": item["size"],
                        "pickcode": item["pickcode"],
                        "url": None,
                        "parent_id": parent_id
                    })
                except Exception:
                    continue
        except Exception as e:
            logger.error(f"扫描目录失败: {str(e)}")
            return files
            
        # 批量获取下载链接
        pickcodes = [f["pickcode"] for f in files]
        url_map = {}
        
        logger.info(f"获取 {len(pickcodes)} 个文件的下载链接...")
        try:
            for url_info in iter_url_batches(
                client=self.client_115,
                pickcodes=pickcodes,
                user_agent=MOBILE_UA,
                batch_size=50,
                headers={"User-Agent": MOBILE_UA}
            ):
                if url_info.url:
                    url_map[url_info.pickcode] = url_info.url
        except Exception as e:
            logger.error(f"获取下载链接失败: {str(e)}")
            
        # 合并下载链接
        for file in files:
            file["url"] = url_map.get(file["pickcode"])
            
        valid_files = [f for f in files if f["url"]]
        logger.info(f"找到 {len(valid_files)} 个有效文件")
        return valid_files
    
    def create_123_directory(self, full_path):
        """创建123云盘目录（已存在时直接使用）"""
        if not full_path:
            return 0
            
        if full_path in self.created_dirs:
            return self.created_dirs[full_path]
            
        parts = [p for p in full_path.split('/') if p]
        current_id = 0
        
        for i, part in enumerate(parts):
            current_path = '/'.join(parts[:i+1])
            
            if current_path in self.created_dirs:
                current_id = self.created_dirs[current_path]
                continue
                
            # 检查目录是否已存在
            existing_id = self.get_123_directory_id(current_id, part)
            if existing_id:
                self.created_dirs[current_path] = existing_id
                current_id = existing_id
                continue
                
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Platform": "open_platform",
                "Content-Type": "application/json"
            }
            
            try:
                response = requests.post(
                    f"{OPEN_API_HOST}{API_PATHS['DIRECTORY_CREATE']}",
                    headers=headers,
                    json={"name": part, "parentID": current_id}
                )
                data = response.json()
                
                if data.get("code") == 0:
                    new_id = data["data"]["dirID"]
                    self.created_dirs[current_path] = new_id
                    current_id = new_id
                else:
                    # 等待后重试获取目录ID
                    time.sleep(1)
                    existing_id = self.get_123_directory_id(current_id, part)
                    if existing_id:
                        self.created_dirs[current_path] = existing_id
                        current_id = existing_id
                    else:
                        # 最终尝试创建
                        response = requests.post(
                            f"{OPEN_API_HOST}{API_PATHS['DIRECTORY_CREATE']}",
                            headers=headers,
                            json={"name": part, "parentID": current_id}
                        )
                        data = response.json()
                        
                        if data.get("code") == 0:
                            new_id = data["data"]["dirID"]
                            self.created_dirs[current_path] = new_id
                            current_id = new_id
                        else:
                            existing_id = self.get_123_directory_id(current_id, part)
                            if existing_id:
                                self.created_dirs[current_path] = existing_id
                                current_id = existing_id
                            else:
                                raise Exception(f"创建目录失败: {data.get('message', '未知错误')}")
            except Exception as e:
                existing_id = self.get_123_directory_id(current_id, part)
                if existing_id:
                    self.created_dirs[current_path] = existing_id
                    current_id = existing_id
                else:
                    logger.error(f"创建目录失败: {str(e)}")
                    raise
                
        return current_id

    def get_123_directory_id(self, parent_id, dir_name):
        """检查目录是否存在"""
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Platform": "open_platform"
        }
        
        try:
            response = requests.get(
                f"{OPEN_API_HOST}{API_PATHS['LIST_FILES_V2']}",
                headers=headers,
                params={"parentFileId": parent_id, "limit": 100}
            )
            data = response.json()
            
            if data.get("code") == 0:
                for item in data["data"]["fileList"]:
                    if item["type"] == 1 and item["filename"] == dir_name:
                        return item["fileId"]
            return None
        except Exception as e:
            logger.error(f"获取目录列表失败: {str(e)}")
            return None

    def submit_to_123pan(self, file_url, file_name, dir_id):
        """提交下载任务到123云盘（带重试机制）"""
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Platform": "open_platform",
            "Content-Type": "application/json"
        }
        
        payload = {"url": file_url, "dirID": dir_id, "fileName": file_name}
        
        for attempt in range(MAX_SUBMIT_RETRIES):
            try:
                response = requests.post(
                    f"{OPEN_API_HOST}{API_PATHS['OFFLINE_DOWNLOAD']}",
                    headers=headers,
                    json=payload
                )
                data = response.json()
                
                if data.get("code") == 0:
                    task_id = data["data"]["taskID"]
                    return task_id
                else:
                    error_msg = data.get("message", "未知错误")
                    # 如果是频率限制错误，等待后重试
                    if "频繁" in error_msg or "稍后" in error_msg:
                        time.sleep(RETRY_DELAY)
                    else:
                        return None
            except Exception:
                time.sleep(RETRY_DELAY)
        
        return None
    def clear_115_directory(self, path=DEFAULT_SOURCE_PATH):
        """清空目录（删除目录下的所有内容但不删除目录本身）"""
        print(f"清空目录: {path}...")
        dir_id = self.find_115_directory_id(path)
        if not dir_id:
            print(f"目录ID未找到: {path}")
            return False
        
        try:
            # 创建文件系统对象
            fs = P115FileSystem(self.client_115)
            
            # 切换到目标目录
            fs.chdir(dir_id)
            
            # 获取目录下的所有文件和子目录
            items = fs.listdir_attr()
            
            # 收集所有要删除的ID
            ids_to_delete = []
            for item in items:
                # 只处理当前目录下的直接子项
                if item['parent_id'] == dir_id:
                    ids_to_delete.append(item['id'])
            
            if not ids_to_delete:
                print(f"目录 {path} 已经是空的")
                return True
            
            # 批量删除
            result = self.client_115.fs_delete(ids_to_delete)
            if result.get("state"):
                print(f"✅ 目录内容删除成功! 已移动到回收站: {path}")
                return True
            else:
                error_msg = result.get("error", "未知错误")
                print(f"❌ 目录内容删除失败: {error_msg}")
                return False
        except Exception as e:
            print(f"清空目录异常: {str(e)}")
            return False

    def get_transfer_report(self):
        """生成迁移统计报告"""
        elapsed = time.time() - self.transfer_stats["start_time"]
        
        report = (
            "📊 迁移统计报告\n"
            "══════════════════════\n"
            f"📂 扫描文件总数: {self.transfer_stats['total_files']} (大小: {format_size(self.transfer_stats['total_size'])})\n"
            f"🚫 过滤文件数: {self.transfer_stats['filtered_files']} (大小: {format_size(self.transfer_stats['filtered_size'])})\n"
            f"📤 提交迁移文件数: {self.transfer_stats['submitted_files']} (大小: {format_size(self.transfer_stats['total_size'] - self.transfer_stats['filtered_size'])})\n"
            f"✅ 成功提交文件数: {self.transfer_stats['success_files']}\n"
            f"❌ 提交失败文件数: {self.transfer_stats['failed_files']}\n"
            f"⏱️ 总耗时: {format_duration(elapsed)}\n"
            "══════════════════════"
        )
        
        return report

    def transfer_files(self, source_path):
        """执行迁移（不再监控进度）"""
        # 重置统计信息
        self.transfer_stats = {
            "total_files": 0,
            "filtered_files": 0,
            "submitted_files": 0,
            "success_files": 0,
            "failed_files": 0,
            "start_time": time.time(),
            "total_size": 0,
            "filtered_size": 0
        }
        
        files = self.scan_115_directory(source_path)
        if not files:
            logger.warning(f"没有可迁移的文件: {source_path}")
            return False, "没有可迁移的文件"
            
        logger.info(f"准备迁移 {len(files)} 个文件...")
        self.transfer_stats["submitted_files"] = len(files)
        
        # 预处理目录 - 提前创建所有需要的目录
        dir_id_map = {}
        for file in files:
            dir_path = file["path"]
            full_dir_path = f"{DEFAULT_SAVE_DIR}/{dir_path}" if dir_path else DEFAULT_SAVE_DIR
            
            if full_dir_path not in dir_id_map:
                try:
                    dir_id = self.create_123_directory(full_dir_path)
                    dir_id_map[full_dir_path] = dir_id
                except Exception as e:
                    logger.error(f"目录创建失败: {str(e)}")
                    parent_path = os.path.dirname(full_dir_path)
                    if parent_path in dir_id_map:
                        dir_id = dir_id_map[parent_path]
                        dir_id_map[full_dir_path] = dir_id
                    else:
                        dir_id_map[full_dir_path] = 0
        
        # 批量提交任务
        success_count = 0
        failed_files = []
        
        for file in files:
            dir_path = file["path"]
            full_dir_path = f"{DEFAULT_SAVE_DIR}/{dir_path}" if dir_path else DEFAULT_SAVE_DIR
            dir_id = dir_id_map.get(full_dir_path, 0)
            
            task_id = self.submit_to_123pan(
                file["url"],
                file["name"],
                dir_id
            )
            
            if task_id:
                success_count += 1
            else:
                failed_files.append(file["name"])
        
        # 更新统计信息
        self.transfer_stats["success_files"] = success_count
        self.transfer_stats["failed_files"] = len(failed_files)
        
        logger.info(f"成功提交任务: {success_count}/{len(files)}")
        if failed_files:
            logger.warning(f"提交失败的文件: {', '.join(failed_files[:3])}{'...' if len(failed_files) > 3 else ''}")
        
        # 生成统计报告
        report = self.get_transfer_report()
        return True, report

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
        self.dispatcher.add_handler(CommandHandler("add", self.add_command))
        self.dispatcher.add_handler(CommandHandler("delete", self.delete_command))
        self.dispatcher.add_handler(CommandHandler("info", self.info_command))
        self.dispatcher.add_handler(CommandHandler("refresh_token", self.refresh_token_command))
        self.dispatcher.add_handler(CommandHandler("transport", self.transport_command))  # 新增迁移命令
        self.dispatcher.add_handler(CommandHandler("clear", self.clear_command))  # 新增清空中转站命令
        self.dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, self.handle_text))
        self.dispatcher.add_handler(MessageHandler(Filters.document, self.handle_document))
        self.dispatcher.add_handler(CallbackQueryHandler(self.button_callback))
        
        # 设置菜单命令
        self.set_menu_commands()
    
    def set_menu_commands(self):
        """设置Telegram Bot菜单命令"""
        commands = [
            BotCommand("start", "个人信息"),
            BotCommand("export", "导出秒传文件"),
            BotCommand("sync_full", "全量同步"),
            BotCommand("info", "用户信息"),
            BotCommand("add", "添加用户"),
            BotCommand("delete", "删除用户"),            
            BotCommand("clear_trash", "清空123回收站"),
            BotCommand("clear", "清空115中转站"),
            BotCommand("transport", "迁移115文件"),  # 新增命令
            BotCommand("refresh_token", "强制刷新Token"),
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
                f"▫️ /clear_trash - 清空123回收站\n"
                f"▫️ /clear - 清空115中转站\n"      # 新增命令
                f"▫️ /transport - 迁移115文件\n\n"  # 新增命令
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
        # 115网盘分享链接处理
        elif re.search(SHARE_LINK_PATTERN, text):
            self.send_auto_delete_message(update, context, "🔗 检测到115分享链接，开始处理...")
            self.handle_115_share_link(update, context, text)
    
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

    @admin_required
    def transport_command(self, update: Update, context: CallbackContext):
        """处理/transport命令 - 迁移115文件到123云盘"""
        args = context.args
        source_path = DEFAULT_SOURCE_PATH
        
        # 解析参数
        if args and args[0] != "默认":
            source_path = ' '.join(args).strip()
        
        self.send_auto_delete_message(update, context, f"🚀 开始迁移任务...\n源路径: {source_path}")
        
        try:
            # 初始化迁移工具
            transfer = Pan115Transfer(
                self.pan_client, 
                self.pan_client.token_manager.access_token
            )
            
            # 执行迁移
            success, report = transfer.transfer_files(source_path)
            
            # 发送结果（不自动删除）
            context.bot.send_message(chat_id=update.message.chat_id, text=report)
        except Exception as e:
            error_msg = f"迁移过程中出错: {str(e)}"
            logger.error(error_msg)
            self.send_auto_delete_message(update, context, f"❌ 迁移失败!\n{error_msg}")

    @admin_required
    def clear_command(self, update: Update, context: CallbackContext):
        """处理/clear命令 - 清空中转站"""
        self.send_auto_delete_message(update, context, f"🧹 正在清空我的接收目录: {DEFAULT_SOURCE_PATH}...")
        try:
            transfer = Pan115Transfer(
                self.pan_client, 
                self.pan_client.token_manager.access_token
            )
            if transfer.clear_115_directory():
                self.send_auto_delete_message(update, context, f"✅ 我的接收目录已清空！", delay=5)
            else:
                self.send_auto_delete_message(update, context, "❌ 清空失败，请检查日志", delay=5)
        except Exception as e:
            error_msg = f"清空中转站时出错: {str(e)}"
            logger.error(error_msg)
            self.send_auto_delete_message(update, context, f"❌ {error_msg}", delay=5)

    @admin_required
    def handle_115_share_link(self, update: Update, context: CallbackContext, text):
        """处理115分享链接"""
        self.send_auto_delete_message(update, context, f"🔗 收到115分享链接，正在处理...")
        
        try:
            # 初始化迁移工具
            transfer = Pan115Transfer(
                self.pan_client, 
                self.pan_client.token_manager.access_token
            )
            
            # 保存分享到115
            success = transfer.save_share_to_115(text)
            
            if success:
                # 等待文件处理 - 减少等待时间
                self.send_auto_delete_message(update, context, "✅ 分享内容已保存到我的接收!\n等待5秒让文件处理完成...", delay=5)
                time.sleep(5)
                
                # 迁移中转站内容
                self.send_auto_delete_message(update, context, "🚀 开始迁移...", delay=5)
                success, report = transfer.transfer_files(DEFAULT_SOURCE_PATH)
                
                # 发送结果（不自动删除）
                context.bot.send_message(chat_id=update.message.chat_id, text=report)
            else:
                self.send_auto_delete_message(update, context, "❌ 保存分享内容失败，请检查链接和密码是否正确", delay=5)
        except Exception as e:
            error_msg = f"处理分享链接时出错: {str(e)}"
            logger.error(error_msg)
            self.send_auto_delete_message(update, context, f"❌ 处理分享链接失败!\n{error_msg}", delay=5)

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
