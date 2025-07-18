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
import httpx
import hashlib
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
from telegram.error import BadRequest
from functools import wraps
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
from p115client import P115Client
from p115client.tool.iterdir import iter_files_with_path, iter_files

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
logging.getLogger("httpx").setLevel(logging.WARNING)

# ====================== 配置区域 ======================
# 数据库文件路径
DB_PATH = os.getenv("DB_PATH", "/data/bot123.db")

# 123云盘API配置
PAN_HOST = "https://www.123pan.com"
API_PATHS = {
    "TOKEN": "/api/v1/access_token",
    "USER_INFO": "/api/v1/user/info",
    "LIST_FILES_V2": "/api/v2/file/list",
    "UPLOAD_REQUEST": "/b/api/file/upload_request",
    "CLEAR_TRASH": "/api/file/trash_delete_all",
    "GET_SHARE": "/b/api/share/get",
    "OFFLINE_DOWNLOAD": "/api/v1/offline/download",  # 新增离线下载API
    "DIRECTORY_CREATE": "/upload/v1/file/mkdir",    # 新增目录创建API
    "OFFLINE_TASK_LIST": "/api/offline_download/task/list",  # 新增离线任务列表API
    "CREATE_SHARE": "/api/v1/share/create", #创建分享链接
    "LIST_SHARE": "/api/v1/share/list" #分享链接列表
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

####123配置
CLIENT_ID = os.getenv("PAN_CLIENT_ID","") #开发者API
CLIENT_SECRET = os.getenv("PAN_CLIENT_SECRET","")  #开发者API
DEFAULT_SAVE_DIR = os.getenv("DEFAULT_SAVE_DIR", "").strip() #JSON和115转存存放目录
EXPORT_BASE_DIRS = [d.strip() for d in os.getenv("EXPORT_BASE_DIR", "").split(';') if d.strip()] #媒体库目录，生成JSON目录
SEARCH_MAX_DEPTH = int(os.getenv("SEARCH_MAX_DEPTH", "")) #扫描目录叠加深度
DAILY_EXPORT_LIMIT = int(os.getenv("DAILY_EXPORT_LIMIT", "3")) #导出次数
BANNED_EXPORT_NAMES = [name.strip().lower() for name in os.getenv("BANNED_EXPORT_NAMES", "电视剧;电影").split(';') if name.strip()] #导出黑名单
PRIVATE_EXPORT = os.getenv("PRIVATE_EXPORT", "Flase").lower() == "true"  # 控制JSON文件是否私聊发送
DEFAULT_SHARE_PASSWORD = os.getenv("DEFAULT_SHARE_PASSWORD", "ZY4K")  # 分享链接默认提取码ZY4K
STRM_SERVICE_URL = os.getenv("STRM_SERVICE_URL", "http://172.17.0.1:8123")  # STRM服务URL
STRM_OUTPUT_DIR = os.getenv("STRM_OUTPUT_DIR", "/data/media")  # STRM文件输出目录
####TGBOT配置
BOT_TOKEN = os.getenv("TG_BOT_TOKEN","")
ADMIN_USER_IDS = [int(id.strip()) for id in os.getenv("TG_ADMIN_USER_IDS", "").split(",") if id.strip()]
####115配置
P115_COOKIE = os.getenv("P115_COOKIE", "")
TARGET_CID = int(os.getenv("TARGET_CID", ""))  # 目标目录ID
USER_AGENT = os.getenv("USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
# API速率控制配置
API_RATE_LIMIT = float(os.getenv("API_RATE_LIMIT", "2.0"))
TRANSFER_RATE_LIMIT = float(os.getenv("TRANSFER_RATE_LIMIT", "3"))
# 允许的文件类型配置
ALLOWED_VIDEO_EXTENSIONS = [ext.strip().lower() for ext in os.getenv("ALLOWED_VIDEO_EXT", ".mp4,.mkv,.avi,.mov,.flv,.wmv,.webm,.ts,.m2ts,.iso,.mp3,.flac,.wav").split(',') if ext.strip()]
ALLOWED_SUB_EXTENSIONS = [ext.strip().lower() for ext in os.getenv("ALLOWED_SUB_EXT", ".srt,.ass,.ssa,.sub,.idx,.vtt,.sup").split(',') if ext.strip()]
ALLOWED_EXTENSIONS = ALLOWED_VIDEO_EXTENSIONS + ALLOWED_SUB_EXTENSIONS  # 合并扩展名
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
                )''',
                '''CREATE TABLE IF NOT EXISTS file_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    etag TEXT NOT NULL,
                    s3KeyFlag TEXT,
                    file_type TEXT NOT NULL,
                    local_path TEXT NOT NULL,
                    unique_hash TEXT NOT NULL UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    media_name TEXT,
                    media_type TEXT
                )'''
            ]
            
            for table in tables:
                c.execute(table)
            
            # 创建索引
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_filename ON directory_cache (filename)",
                "CREATE INDEX IF NOT EXISTS idx_full_path ON directory_cache (full_path)",
                "CREATE INDEX IF NOT EXISTS idx_base_dir ON directory_cache (base_dir_id)",
                "CREATE INDEX IF NOT EXISTS idx_unique_hash ON file_records (unique_hash)",
                "CREATE INDEX IF NOT EXISTS idx_file_path ON file_records (file_path)"
            ]
            # 执行创建表和索引
            for table in tables:
                c.execute(table)
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


def format_time(seconds):
    """将秒数格式化为 HH:MM:SS"""
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"

def parse_share_link(share_link):
    """解析115分享链接"""
    match = re.search(r"https?://115(?:cdn)?\.com/s/(\w+)\?password=(\w+)", share_link)
    if not match:
        raise ValueError("无效的115分享链接格式")
    return match.group(1), match.group(2)

def get_relative_path(full_path):
    """获取相对于根目录的路径，正确处理根目录下的文件"""
    # 移除开头的斜杠
    normalized_path = full_path.lstrip('/')
    
    # 如果路径为空，说明是根目录下的文件
    if not normalized_path:
        return ""
    
    # 如果路径中不含斜杠，说明文件在根目录下
    if '/' not in normalized_path:
        return ""
    
    # 否则返回除第一级目录外的所有路径（目录部分）
    parts = normalized_path.split('/')
    return '/'.join(parts[1:-1])  # 修改这里：排除最后一部分（文件名）

def is_allowed_file(filename):
    """检查文件扩展名是否在允许列表中"""
    _, ext = os.path.splitext(filename)
    return ext.lower() in ALLOWED_EXTENSIONS

def calculate_unique_hash(size, etag, s3KeyFlag):
    """计算唯一标识哈希"""
    return hashlib.md5(f"{size}|{etag}|{s3KeyFlag}".encode()).hexdigest()

def get_media_library_stats():
    """从数据库获取媒体库统计信息"""
    stats = {
        'movie_count': 0,
        'movie_size': 0,
        'tv_count': 0,
        'tv_size': 0,
        'sub_count': 0,
        'sub_size': 0,
        'total_count': 0,
        'total_size': 0
    }
    
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # 电影统计（按media_name去重）
            c.execute("""
                SELECT COUNT(DISTINCT media_name) AS count, SUM(size) AS total_size 
                FROM file_records 
                WHERE media_type = 'movie' AND file_type = 'video'
            """)
            movie = c.fetchone()
            if movie:
                stats['movie_count'] = movie['count'] or 0
                stats['movie_size'] = movie['total_size'] or 0
            
            # 电视剧统计（按media_name去重）
            c.execute("""
                SELECT COUNT(DISTINCT media_name) AS count, SUM(size) AS total_size 
                FROM file_records 
                WHERE media_type = 'tv' AND file_type = 'video'
            """)
            tv = c.fetchone()
            if tv:
                stats['tv_count'] = tv['count'] or 0
                stats['tv_size'] = tv['total_size'] or 0
            
            # 字幕统计
            c.execute("""
                SELECT COUNT(*) AS count, SUM(size) AS total_size 
                FROM file_records 
                WHERE file_type = 'subtitle'
            """)
            sub = c.fetchone()
            if sub:
                stats['sub_count'] = sub['count'] or 0
                stats['sub_size'] = sub['total_size'] or 0
            
            # 总体统计
            c.execute("SELECT COUNT(*) AS count, SUM(size) AS total_size FROM file_records")
            total = c.fetchone()
            if total:
                stats['total_count'] = total['count'] or 0
                stats['total_size'] = total['total_size'] or 0
                
    except Exception as e:
        logger.error(f"获取媒体库统计失败: {e}")
    
    return stats
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

class STRMGenerator:

    def extract_media_info(self, relative_path):
        """从文件路径提取媒体名称和类型（改进版）"""
        # 标准化路径并分割
        path_parts = relative_path.strip('/').split('/')
        
        # 如果路径为空，返回空值
        if not path_parts:
            return "", ""
        
        # 如果路径深度为1（只有文件名），则按电影处理
        if len(path_parts) == 1:
            # 只有文件名，没有目录 - 按电影处理
            return os.path.splitext(path_parts[0])[0], "movie"
        
        # 检查最后一个目录是否为季目录
        last_dir = path_parts[-2]  # 最后一部分是文件名，倒数第二部分是目录
        
        # 定义季目录的正则表达式模式（不区分大小写）
        season_patterns = [
            r"^season\s*\d+$",      # Season 1, Season 01
            r"^s\d+$",               # S1, S01
            r"^第\s*\d+\s*季$",       # 第1季, 第 1 季
            r"^season\s*\d+$",       # Season1 (无空格)
            r"^series\s*\d+$",       # Series 1
        ]
        
        last_dir_lower = last_dir.lower().strip()
        
        for pattern in season_patterns:
            if re.match(pattern, last_dir_lower):
                # 季目录格式 - 电视剧
                if len(path_parts) > 2:
                    # 媒体名称为倒数第二个目录
                    media_name = path_parts[-3]
                else:
                    # 如果路径深度只有2（如：剧集名/Season 01/文件），则使用第一个目录
                    media_name = path_parts[0] if path_parts else ""
                return media_name, "tv"
        
        # 非季目录格式 - 电影
        media_name = last_dir
        return media_name, "movie"

    def record_file_info(self, file_path, file_name, size, etag, s3KeyFlag, file_type, local_path, relative_path):
        """记录文件信息到数据库（支持字幕文件）"""
        try:
            unique_hash = calculate_unique_hash(size, etag, s3KeyFlag)
            media_name, media_type = self.extract_media_info(relative_path)
            
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                c.execute('''INSERT OR IGNORE INTO file_records 
                            (file_path, file_name, size, etag, s3KeyFlag, file_type, local_path, unique_hash, media_name, media_type)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                          (file_path, file_name, size, etag, s3KeyFlag, file_type, local_path, unique_hash, media_name, media_type))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"记录文件信息失败: {e}")
            return False
        
    def generate_strm_files_recursive(self, directory_id, base_path="", prefix_to_remove=""):
        """递归生成STRM文件和下载字幕文件"""
        generated_count = 0
        last_file_id = 0
        
        # 使用完整路径作为目录名称
        current_dir_path = base_path if base_path else "根目录"
        
        while True:
            # 获取当前目录文件列表
            url = f"{OPEN_API_HOST}{API_PATHS['LIST_FILES_V2']}"
            params = {
                "parentFileId": directory_id,
                "trashed": 0,
                "limit": 100,
                "lastFileId": last_file_id
            }
            headers = self.pan_client.token_manager.get_auth_header()
            
            try:
                response = self.pan_client._call_api("GET", url, params=params, headers=headers, timeout=30)
                if not response or response.status_code != 200:
                    return generated_count
                
                data = response.json()
                if data.get("code") != 0:
                    return generated_count
                
                # 批量处理文件
                video_items = []
                sub_items = []
                for item in data["data"].get("fileList", []):
                    if item.get("trashed", 1) != 0:
                        continue
                    # 构建文件路径时去掉媒体库目录部分
                    file_full_path = f"{base_path}/{item['filename']}" if base_path else item['filename']

                    if item["type"] == 0:  # 文件
                        # 移除媒体库前缀
                        relative_path = file_full_path
                        if prefix_to_remove and file_full_path.startswith(prefix_to_remove):
                            relative_path = file_full_path[len(prefix_to_remove):].lstrip('/')
                        
                        ext = os.path.splitext(item['filename'])[1].lower()
                        # 处理视频文件
                        if ext in ALLOWED_VIDEO_EXTENSIONS:
                            video_items.append((relative_path, item))
                        # 处理字幕文件
                        elif ext in ALLOWED_SUB_EXTENSIONS:
                            sub_items.append((relative_path, item))

                    elif item["type"] == 1:  # 目录
                        # 构建目录路径时去掉媒体库目录部分
                        dir_full_path = f"{base_path}/{item['filename']}" if base_path else item['filename']

                        # 递归处理子目录
                        sub_count = self.generate_strm_files_recursive(item["fileId"], dir_full_path, prefix_to_remove)
                        generated_count += sub_count
                
                # 批量生成STRM文件
                if video_items:
                    count = self._batch_create_strm_files(video_items)
                    generated_count += count
                    logger.info(f"在目录 '{current_dir_path}' 下生成 {count} 个视频STRM文件")
                
                # 批量下载字幕文件
                if sub_items:
                    sub_count = self._batch_download_subtitles(sub_items)
                    logger.info(f"在目录 '{current_dir_path}' 下下载 {sub_count} 个字幕文件")
                
                last_file_id = data["data"].get("lastFileId", -1)
                if last_file_id == -1:
                    break
                    
            except Exception as e:
                logger.error(f"处理目录 '{current_dir_path}' 时出错: {str(e)}")
                return generated_count
        
        return generated_count

    def _batch_create_strm_files(self, file_items):
        """批量创建STRM文件"""
        count = 0
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            for relative_path, item in file_items:
                futures.append(executor.submit(self._create_single_strm_file, relative_path, item))

            for future in as_completed(futures):
                if future.result():
                    count += 1
        return count
    
    def _batch_download_subtitles(self, sub_items):
        """批量下载字幕文件"""
        count = 0
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            for relative_path, item in sub_items:
                futures.append(executor.submit(self._download_single_subtitle, relative_path, item))

            for future in as_completed(futures):
                if future.result():
                    count += 1
        return count
    
    def _create_single_strm_file(self, relative_path, item):
        """创建单个STRM文件（保留目录结构）"""
        try:
            # 创建输出路径 - 使用相对路径
            file_name = os.path.basename(relative_path)
            file_name_without_ext = os.path.splitext(file_name)[0]
            dir_path = os.path.dirname(relative_path)
            
            # 构建STRM文件路径
            strm_file_path = os.path.join(STRM_OUTPUT_DIR, dir_path, f"{file_name_without_ext}.strm")
            
            # 创建目录结构
            os.makedirs(os.path.dirname(strm_file_path), exist_ok=True)
            
            # 生成STRM内容
            strm_content = (
                f"{STRM_SERVICE_URL}/"
                f"{file_name}|"
                f"{item['size']}|"
                f"{item['etag']}?"
                f"{item.get('s3KeyFlag')}"
            )
            
            # 写入文件
            with open(strm_file_path, 'w', encoding='utf-8') as f:
                f.write(strm_content)
            
            # 提取媒体信息
            media_name, media_type = self.extract_media_info(relative_path)
            
            # 记录文件信息到数据库
            file_type = "video" 
            file_path = item.get('path', relative_path)  # 获取123云盘中的完整路径
            self.record_file_info(
                file_path=file_path,
                file_name=file_name,
                size=item['size'],
                etag=item['etag'],
                s3KeyFlag=item.get('s3KeyFlag'),
                file_type=file_type,
                local_path=strm_file_path,
                relative_path=relative_path  # 添加相对路径参数
            )
            
            return True
        except Exception as e:
            logger.error(f"生成STRM文件失败: {relative_path} - {str(e)}")
            return False

    def _download_single_subtitle(self, relative_path, item):
        """下载单个字幕文件并记录到数据库"""
        try:
            # 获取文件信息
            file_name = os.path.basename(relative_path)
            dir_path = os.path.dirname(relative_path)
            
            # 构建本地保存路径
            local_path = os.path.join(STRM_OUTPUT_DIR, dir_path, file_name)
            
            # 创建目录（如果不存在）
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            # 获取文件下载链接
            download_url = self._get_subtitle_download_url(item)
            
            # 下载文件
            if download_url:
                self._download_file(download_url, local_path)
                
            # 提取媒体信息
            media_name, media_type = self.extract_media_info(relative_path)
            
            # 记录到数据库
            self.record_file_info(
                file_path=relative_path,
                file_name=file_name,
                size=item['size'],
                etag=item['etag'],
                s3KeyFlag=item.get('s3KeyFlag'),
                file_type="subtitle",
                local_path=local_path,
                relative_path=relative_path  # 添加相对路径参数
            )
            return True
        except Exception as e:
            logger.error(f"下载字幕文件失败: {relative_path} - {str(e)}")
            return False

    def _get_subtitle_download_url(self, item):
        """生成字幕文件下载URL"""
        try:
            return (
                f"{STRM_SERVICE_URL}/"
                f"{item['filename']}|"
                f"{item['size']}|"
                f"{item['etag']}?"
                f"{item.get('s3KeyFlag')}"
            )
        except Exception as e:
            logger.error(f"生成字幕下载URL失败: {str(e)}")
            return None

    def _download_file(self, url, save_path):
        """下载文件到本地"""
        try:
            # 使用带重试机制的下载
            for attempt in range(3):
                try:
                    response = requests.get(url, stream=True, timeout=30)
                    response.raise_for_status()
                    
                    with open(save_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                    return True
                except (requests.exceptions.RequestException, IOError) as e:
                    logger.warning(f"文件下载失败（尝试 {attempt+1}/3）: {save_path} - {str(e)}")
                    time.sleep(2)
            return False
        except Exception as e:
            logger.error(f"文件下载异常: {save_path} - {str(e)}")
            return False
        
    def restore_strm_files_from_db(self):
        """从数据库恢复STRM文件和字幕文件（修复路径和列名问题）"""
        try:
            video_count = 0
            sub_count = 0
            video_errors = 0
            sub_errors = 0
            
            with closing(sqlite3.connect(DB_PATH)) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("SELECT * FROM file_records")
                rows = c.fetchall()
                
                if not rows:
                    return "❌ 数据库中没有找到任何文件记录"
                
                # 处理视频文件
                for row in rows:
                    try:
                        # 修复列名大小写问题：使用小写列名访问
                        file_type = row["file_type"]
                        local_path = row["local_path"]
                        
                        # 统一路径分隔符为当前系统的正确格式
                        normalized_path = os.path.normpath(local_path)
                        
                        if file_type == "video":
                            # 获取视频文件信息
                            file_name = row["file_name"]
                            size = row["size"]
                            etag = row["etag"]
                            s3KeyFlag = row["s3KeyFlag"]
                            
                            # 重新生成STRM内容
                            strm_content = (
                                f"{STRM_SERVICE_URL}/"
                                f"{file_name}|"
                                f"{size}|"
                                f"{etag}?"
                                f"{s3KeyFlag}"
                            )
                            
                            # 确保目录存在
                            os.makedirs(os.path.dirname(normalized_path), exist_ok=True)
                            
                            # 写入STRM文件
                            with open(normalized_path, 'w', encoding='utf-8') as f:
                                f.write(strm_content)
                            
                            video_count += 1
                            
                        elif file_type == "subtitle":
                            # 获取字幕文件信息
                            file_name = row["file_name"]
                            size = row["size"]
                            etag = row["etag"]
                            s3KeyFlag = row["s3KeyFlag"]
                            
                            # 生成下载URL
                            download_url = (
                                f"{STRM_SERVICE_URL}/"
                                f"{file_name}|"
                                f"{size}|"
                                f"{etag}?"
                                f"{s3KeyFlag}"
                            )
                            
                            # 确保目录存在
                            os.makedirs(os.path.dirname(normalized_path), exist_ok=True)
                            
                            # 下载字幕文件
                            if self._download_file(download_url, normalized_path):
                                sub_count += 1
                                
                    except Exception as e:
                        if file_type == "video":
                            logger.error(f"恢复视频STRM文件失败: {normalized_path} - {str(e)}", exc_info=True)
                            video_errors += 1
                        elif file_type == "subtitle":
                            logger.error(f"恢复字幕文件失败: {normalized_path} - {str(e)}", exc_info=True)
                            sub_errors += 1
                
                return (
                    f"✅ 恢复完成！\n"
                    f"├ 视频STRM文件: {video_count}个 (失败: {video_errors})\n"
                    f"└ 字幕文件: {sub_count}个 (失败: {sub_errors})"
                )
                
        except Exception as e:
            logger.error(f"从数据库恢复文件失败: {str(e)}", exc_info=True)
            return f"❌ 恢复失败: {str(e)}"


    def search_media(self, keyword):
        """在数据库中搜索媒体"""
        results = []
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                # 按media_name分组统计
                c.execute("""
                    SELECT media_name, media_type, 
                           COUNT(*) AS file_count, 
                           SUM(size) AS total_size,
                           GROUP_CONCAT(local_path) AS sample_paths
                    FROM file_records
                    WHERE media_name LIKE ?
                    GROUP BY media_name, media_type
                    ORDER BY media_name
                """, (f'%{keyword}%',))
                
                for row in c.fetchall():
                    # 提取示例路径（取第一个路径）
                    sample_path = row["sample_paths"].split(',')[0] if row["sample_paths"] else ""
                    # 提取到媒体名称目录
                    if sample_path and row["media_name"]:
                        # 尝试找到媒体名称在路径中的位置
                        media_index = sample_path.find(row["media_name"])
                        if media_index != -1:
                            sample_path = sample_path[:media_index + len(row["media_name"])]
                    
                    results.append({
                        "media_name": row["media_name"],
                        "media_type": row["media_type"],
                        "file_count": row["file_count"],
                        "total_size": row["total_size"],
                        "sample_path": sample_path
                    })
        except Exception as e:
            logger.error(f"媒体搜索失败: {e}")
        return results
    
    def delete_media(self, media_name):
        """从数据库中删除媒体记录"""
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                c = conn.cursor()
                c.execute("DELETE FROM file_records WHERE media_name = ?", (media_name,))
                conn.commit()
                return c.rowcount
        except Exception as e:
            logger.error(f"删除媒体失败: {e}")
            return 0
    
    def export_media_json(self, media_name):
        """导出媒体JSON文件"""
        try:
            with closing(sqlite3.connect(DB_PATH)) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("""
                    SELECT file_path, etag, size 
                    FROM file_records 
                    WHERE media_name = ?
                """, (media_name,))
                
                files = []
                for row in c.fetchall():
                    files.append({
                        "path": row["file_path"],
                        "etag": row["etag"],
                        "size": row["size"]
                    })
                
                if not files:
                    return None
                
                # 创建JSON结构
                json_data = {
                    "usesBase62EtagsInExport": False,
                    "commonPath": "",
                    "totalFilesCount": len(files),
                    "totalSize": sum(f["size"] for f in files),
                    "formattedTotalSize": format_size(sum(f["size"] for f in files)),
                    "files": files
                }
                
                # 保存到临时文件
                file_name = f"{re.sub(r'[\\/*?:\"<>|]', '', media_name)}.json"
                with open(file_name, "w", encoding="utf-8") as f:
                    json.dump(json_data, f, ensure_ascii=False, indent=2)
                
                return file_name
        except Exception as e:
            logger.error(f"导出媒体JSON失败: {e}")
            return None

class Pan123API:
    """123云盘API客户端"""
    def __init__(self, token_manager):
        self.token_manager = token_manager
    
    def get_access_token(self):
        """获取访问令牌"""
        return self.token_manager.access_token
    
    def get_base_directory(self):
        """获取基础目录ID，如果不存在则创建"""
        return self.find_or_create_directory(0, DEFAULT_SAVE_DIR)
    
    def find_or_create_directory(self, parent_id, dir_name):
        """查找或创建目录"""
        access_token = self.get_access_token()
        if not access_token:
            return None
        
        # 查找目录
        url = f"{OPEN_API_HOST}{API_PATHS['LIST_FILES_V2']}"
        headers = {
            "Authorization": access_token,
            "Platform": "open_platform"
        }
        params = {
            "parentFileId": parent_id,
            "limit": 100,
            "trashed": False
        }
        
        try:
            response = httpx.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            # 检查目录是否已存在
            for item in data.get("data", {}).get("fileList", []):
                if item["type"] == 1 and item["filename"] == dir_name and not item["trashed"]:
                    return item["fileId"]
            
            # 创建新目录
            url = f"{OPEN_API_HOST}{API_PATHS['DIRECTORY_CREATE']}"
            payload = {
                "name": dir_name,
                "parentID": parent_id
            }
            headers["Content-Type"] = "application/json"
            response = httpx.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()

            if isinstance(data.get("data"), dict) and "dirID" in data["data"]:
                return data["data"]["dirID"]
            elif data.get("code") and data.get("message"):
                if data.get("code") == 1 and "同名文件夹" in data.get("message", ""):
                    logger.info(f"目录已存在: {dir_name}, 直接使用父目录ID: {parent_id}")
                    return parent_id
                else:
                    logger.error(f"创建目录失败: 错误码 {data['code']} - {data['message']}")
            else:
                logger.error(f"创建目录失败: {data.get('message', '未知错误')}")
            return None
        except Exception as e:
            logger.error(f"123云盘目录操作失败: {str(e)}")
            return None
    
    def ensure_directory_path(self, target_path):
        """确保目录路径存在，返回最后一级目录ID"""
        current_dir_id = 0
        
        # 确保基础目录存在
        base_dir_id = self.find_or_create_directory(current_dir_id, DEFAULT_SAVE_DIR)
        if not base_dir_id:
            logger.error(f"无法创建基础目录: {DEFAULT_SAVE_DIR}")
            return None
        
        # 处理目标路径
        path_parts = target_path.split('/')
        
        # 创建路径
        current_dir_id = base_dir_id
        for part in path_parts:
            if not part.strip():
                continue
            new_dir_id = self.find_or_create_directory(current_dir_id, part)
            if not new_dir_id:
                return None
            current_dir_id = new_dir_id
        
        return current_dir_id
    
    def get_offline_task_count(self):
        """获取当前离线任务数量（等待+运行中）"""
        # 注意：离线任务列表API需要使用网页版认证
        access_token = self.get_access_token()
        if not access_token:
            logger.warning("无法获取访问令牌")
            return None
        
        # 使用网页版API获取离线任务列表
        url = f"{PAN_HOST}{API_PATHS['OFFLINE_TASK_LIST']}"
        headers = {
            "Authorization": f"Bearer {access_token}",  # 使用Bearer token认证
            "Platform": "open_platform",
            "Content-Type": "application/json"
        }
        payload = {
            "current_page": 1,
            "page_size": 100,
            "status_arr": [0, 1]  # 0:等待 1:运行
        }
        
        try:
            response = httpx.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            # 检查响应代码
            if data.get("code") != 0:
                logger.warning(f"离线任务列表API返回错误代码: {data.get('code')}, 消息: {data.get('message')}")
                return None
                
            # 从响应中提取任务列表
            task_list = []
            
            # 处理data部分
            data_section = data.get("data", {})
            
            # 情况1: data_section是字典，包含list字段
            if isinstance(data_section, dict):
                # 检查list字段
                if "list" in data_section and isinstance(data_section["list"], list):
                    task_list = data_section["list"]
                # 检查total字段（当list为None时使用total）
                elif "total" in data_section and data_section["total"] is not None:
                    logger.info(f"使用total字段获取任务数量: {data_section['total']}")
                    return int(data_section["total"])
            
            # 情况2: data_section是列表
            elif isinstance(data_section, list):
                task_list = data_section
            
            # 如果成功获取到任务列表
            if isinstance(task_list, list):
                logger.info(f"成功获取离线任务列表，任务数量: {len(task_list)}")
                return len(task_list)
            else:
                # 尝试使用total字段作为后备
                total_tasks = data_section.get("total")
                if total_tasks is not None:
                    logger.info(f"使用total字段获取任务数量: {total_tasks}")
                    return int(total_tasks)
                
                logger.warning(f"无法解析离线任务列表，响应类型: {type(data_section)}")
                return None
                
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP错误({e.response.status_code}): {e.response.text}")
            return None
        except Exception as e:
            logger.error(f"获取离线任务数量失败: {str(e)}")
            return None
    
    def wait_for_task_slot(self, max_queue_size=10, retry_interval=10):
        """
        无限期等待直到有可用的任务槽位
        :param max_queue_size: 最大允许队列大小
        :param retry_interval: 重试间隔(秒)
        """
        while True:
            try:
                task_count = self.get_offline_task_count()
                
                if task_count is None:
                    logger.warning("获取任务队列状态失败，等待后重试...")
                    time.sleep(retry_interval)
                    continue
                    
                if task_count < max_queue_size:
                    logger.info(f"当前任务队列: {task_count}/{max_queue_size}，有空位可用")
                    return
                else:
                    logger.info(f"当前任务队列已满: {task_count}/{max_queue_size}，等待中...")
                    time.sleep(retry_interval)
            except Exception as e:
                logger.error(f"等待任务槽位时出错: {str(e)}")
                time.sleep(retry_interval)
    
    def create_offline_task_with_retry(self, url, file_name, dir_id, max_retries=20):
        """创建123云盘离线下载任务（带重试机制）"""
        for attempt in range(1, max_retries + 1):
            try:
                task_id = self.create_offline_task(url, file_name, dir_id)
                if task_id:
                    return task_id
                else:
                    logger.warning(f"第 {attempt}/{max_retries} 次尝试失败: {file_name}")
            except Exception as e:
                logger.warning(f"第 {attempt}/{max_retries} 次尝试失败: {str(e)}")
            
            # 如果不是最后一次尝试，等待一段时间再重试
            if attempt < max_retries:
                wait_time = 2 * attempt  # 指数退避策略
                logger.info(f"等待 {wait_time} 秒后重试...")
                time.sleep(wait_time)
        
        logger.error(f"创建离线任务失败: 已达到最大重试次数 ({max_retries})")
        return None
    
    def create_offline_task(self, url, file_name, dir_id):
        """创建123云盘离线下载任务"""
        access_token = self.token_manager.access_token
        if not access_token:
            raise ValueError("无法获取有效的访问令牌")
        
        url_api = f"{OPEN_API_HOST}{API_PATHS['OFFLINE_DOWNLOAD']}"
        headers = {
            "Authorization": access_token,
            "Platform": "open_platform",
            "Content-Type": "application/json"
        }
        payload = {
            "url": url,
            "fileName": file_name,
            "dirID": dir_id,
            "callBackUrl": "http://example.com/callback"  
        }
        
        try:
            response = requests.post(url_api, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            if "data" in data and "taskID" in data["data"]:
                return data["data"]["taskID"]
            else:
                error_msg = data.get("message", "未知错误")
                logger.error(f"离线任务创建失败: {error_msg}")
                return None
        except requests.HTTPError as e:
            logger.error(f"HTTP错误: {e.response.status_code} - {e.response.text}")
            return None
        except Exception as e:
            logger.error(f"创建离线下载任务失败: {str(e)}")
            return None

class Pan115to123Transfer:
    """115至123云盘迁移核心逻辑"""
    def __init__(self, p115_cookie, target_cid, user_agent,
                 pan123_api, allowed_extensions):
        self.p115_cookie = p115_cookie
        self.target_cid = target_cid
        self.user_agent = user_agent
        self.pan123 = pan123_api
        self.allowed_extensions = allowed_extensions
        self.lock = threading.Lock()  # 添加线程锁
        self.active_transfers = {}    # 跟踪活跃迁移任务
        
        # 创建115客户端
        try:
            self.client_115 = P115Client(p115_cookie)
            logger.info("115客户端创建成功")
        except Exception as e:
            logger.error(f"创建115客户端失败: {str(e)}")
            self.client_115 = None
        
        # 初始化统计信息
        self.stats = {
            "total_files": 0,
            "filtered_files": 0,
            "to_transfer_files": 0,
            "success_count": 0,
            "fail_count": 0,
            "total_size": 0,
            "filtered_size": 0,
            "transfer_size": 0,
            "elapsed_time": 0,
            "failed_files": []
        }
    
    def reset_stats(self):
        """重置统计信息"""
        self.stats = {
            "total_files": 0,
            "filtered_files": 0,
            "to_transfer_files": 0,
            "success_count": 0,
            "fail_count": 0,
            "total_size": 0,
            "filtered_size": 0,
            "transfer_size": 0,
            "elapsed_time": 0,
            "failed_files": []
        }

    def save_share_to_115(self, share_link, target_cid):
        """保存分享链接到指定目录"""
        try:
            share_code, password = parse_share_link(share_link)
            logger.info(f"解析分享链接成功 - 分享码: {share_code}")
            
            # ===== 修改点：使用正确的API调用方式 =====
            # 创建payload字典
            payload = {
                'share_code': share_code,
                'receive_code': password,
                'cid': target_cid
            }
            
            # 接收分享内容到目标目录
            resp = self.client_115.share_receive(payload)
            
            if resp.get("state") is True:
                logger.info(f"分享内容保存成功，目录ID: {target_cid}")
                return target_cid
            else:
                error = resp.get("error", "未知错误")
                logger.error(f"分享内容保存失败: {error}")
                return None
        except Exception as e:
            logger.error(f"保存分享链接失败: {str(e)}")
            return None
        
    def mark_file_as_processed(self, file_id):
        """标记文件为已处理（添加星标）"""
        try:
            # 使用 fs_star_set 方法添加星标
            result = self.client_115.fs_star_set(file_id, star=True)
            if result.get('state') is True:
                logger.info(f"文件标记成功: {file_id}")
                return True
            else:
                logger.error(f"文件标记失败: {result.get('error')}")
                return False
        except Exception as e:
            logger.error(f"标记文件失败: {str(e)}")
            return False
              
    def migrate(self, share_link=None, user_id=None):
        """执行115到123云盘的迁移任务（支持后台线程）"""
        # 重置统计信息
        self.reset_stats()
        
        # 为每个用户创建唯一的任务ID
        task_id = f"{user_id}_{int(time.time())}" if user_id else "system_{}".format(int(time.time()))
        with self.lock:
            self.active_transfers[task_id] = {
                "status": "running",
                "start_time": time.time(),
                "stats_ref": self.stats  # 直接引用实时更新的统计信息字典
            }
        
        # 在后台线程中执行迁移
        def _run_migration():
            start_time = time.time()
            logger.info("115分享链接处理脚本开始执行")
            
            if not self.client_115:
                logger.error("115客户端不可用")
                result = self._build_result(False, "115客户端不可用")
                with self.lock:
                    self.active_transfers[task_id].update({
                        "status": "completed",
                        "end_time": time.time(),
                        "result": result
                    })
                return
            
            saved_cid = self.target_cid
            
            # 处理分享链接（如果提供）
            if share_link:
                # 使用新的保存方法
                result_cid = self.save_share_to_115(share_link, self.target_cid)
                if result_cid:
                    saved_cid = result_cid
                    time.sleep(5)  # 等待文件处理完成
                else:
                    result = self._build_result(False, "分享内容保存失败")
                    with self.lock:
                        self.active_transfers[task_id].update({
                            "status": "completed",
                            "end_time": time.time(),
                            "result": result
                        })
                    return
            
            # 按目录层级收集文件信息
            directory_files = self._collect_files_by_directory(saved_cid)
            if not directory_files:
                result = self._build_result(False, "收集文件路径失败")
                with self.lock:
                    self.active_transfers[task_id].update({
                        "status": "completed",
                        "end_time": time.time(),
                        "result": result
                    })
                return
            
            # 处理文件迁移
            self._process_files_by_directory(directory_files)
            
            self.stats["elapsed_time"] = time.time() - start_time
            result = self._build_result(True, "迁移任务完成")
            with self.lock:
                self.active_transfers[task_id].update({
                    "status": "completed",
                    "end_time": time.time(),
                    "result": result
                })
        
        threading.Thread(target=_run_migration, daemon=True).start()
        return task_id  # 返回任务ID用于查询状态
    
    def _collect_files_by_directory(self, cid):
        """按目录层级收集文件"""
        logger.info(f"开始按目录层级收集文件信息（只处理允许的文件类型）...")
        directory_files = {}
        seen_ids = set()  # 用于跟踪已处理的文件ID
        
        try:
            # 使用 iter_files_with_path 获取所有文件（包含路径）
            logger.info(f"开始遍历目录树，根目录ID: {cid}")
            all_files = iter_files_with_path(
                client=self.client_115,
                cid=cid,
                cur=0,  # 递归遍历子目录
                app="web"  # 使用web接口
            )
            
            file_count = 0
            # 按目录分组文件
            for file_info in all_files:
                # 跳过目录
                if file_info.get("is_directory"):
                    continue

                file_id = file_info["id"]
                # 检查是否已处理过此文件
                if file_id in seen_ids:
                    continue
                seen_ids.add(file_id)
                
                # 检查文件是否已标记（已处理）
                if file_info.get('star') == 1:
                    logger.info(f"文件已标记，跳过: {file_info.get('name')}")
                    continue
                
                file_count += 1
                self.stats["total_files"] += 1
                file_size = file_info.get("size", 0)
                self.stats["total_size"] += file_size
                
                file_name = file_info.get("name")
                # 获取文件完整路径
                full_path = file_info.get("path", "")
                
                # 获取相对于根目录的路径（排除第一级目录）
                dir_path = get_relative_path(full_path)
                
                logger.info(f"处理文件: {file_name} | 路径: {full_path} | 相对路径: {dir_path} | 大小: {format_size(file_size)}")
                
                # 检查文件扩展名
                if is_allowed_file(file_name):
                    # 添加到对应目录
                    if dir_path not in directory_files:
                        directory_files[dir_path] = []
                    directory_files[dir_path].append({
                        "id": file_info["id"],
                        "pickcode": file_info.get("pickcode"),
                        "name": file_name,
                        "size": file_size
                    })
                    self.stats["to_transfer_files"] += 1
                    self.stats["transfer_size"] += file_size
                else:
                    self.stats["filtered_files"] += 1
                    self.stats["filtered_size"] += file_size
            
            logger.info(f"遍历完成，共找到 {file_count} 个文件")
            logger.info(f"按目录层级收集完成，共 {len(directory_files)} 个目录")
            return directory_files
        except Exception as e:
            logger.error(f"按目录收集文件时出错: {str(e)}")
            logger.error(f"错误详情: {traceback.format_exc()}")
            return None
    def _process_files_by_directory(self, directory_files):
        """按目录处理文件迁移到123云盘"""
        logger.info("开始按目录批量迁移文件到123云盘...")
        
        # 获取基础目录ID（"待整理"目录）
        base_dir_id = self.pan123.get_base_directory()
        if not base_dir_id:
            logger.error("无法获取基础目录ID")
            return
        
        # 先处理根目录文件（路径为""）
        if "" in directory_files:
            root_files = directory_files[""]
            logger.info(f"处理根目录下的 {len(root_files)} 个文件")
            self._process_directory_files("", base_dir_id, root_files)
        
        # 处理其他目录
        for dir_path, files in directory_files.items():
            if dir_path == "":  # 根目录已处理
                continue
            
            # 确保目录路径存在
            logger.info(f"确保目录路径存在: {dir_path}")
            target_dir_id = self.pan123.ensure_directory_path(dir_path)
            
            if not target_dir_id:
                logger.error(f"目录创建失败: {dir_path}")
                # 记录该目录下所有文件为失败
                for file_info in files:
                    self.stats["fail_count"] += 1
                    self.stats["failed_files"].append(file_info['name'])
                continue
            
            # 处理该目录下的文件
            self._process_directory_files(dir_path, target_dir_id, files)

    def _process_directory_files(self, dir_path, dir_id, files):
        """处理单个目录下的所有文件"""
        logger.info(f"处理目录 '{dir_path or '根目录'}' 下的 {len(files)} 个文件")
        
        for file_info in files:
            try:
                # 无限期等待直到有可用的任务槽位
                logger.info(f"等待可用任务槽位: {file_info['name']}")
                self.pan123.wait_for_task_slot()
                
                # 获取文件下载链接
                logger.info(f"获取下载链接: {file_info['name']}")
                file_url = self.client_115.download_url(
                    file_info['pickcode'],  # 位置参数
                    headers={"User-Agent": self.user_agent}
                )
                
                if not file_url:
                    logger.warning(f"文件无有效下载链接: {file_info['name']}")
                    self.stats["fail_count"] += 1
                    self.stats["failed_files"].append(file_info['name'])
                    continue
                
                # 创建离线下载任务
                logger.info(f"创建离线任务: {file_info['name']}")
                task_id = self.pan123.create_offline_task_with_retry(
                    file_url, file_info['name'], dir_id
                )
                
                if task_id:
                    self.stats["success_count"] += 1
                    
                    # 标记文件为已处理
                    self.mark_file_as_processed(file_info['id'])
                    
                    # 提交后短暂等待，避免请求过于频繁
                    time.sleep(2)
                else:
                    logger.error(f"离线任务创建失败: {file_info['name']}")
                    self.stats["fail_count"] += 1
                    self.stats["failed_files"].append(file_info['name'])
            except Exception as e:
                logger.error(f"处理文件 {file_info['name']} 失败: {str(e)}")
                self.stats["fail_count"] += 1
                self.stats["failed_files"].append(file_info['name'])

    def _build_result(self, success, message):
        """构建结果字典"""
        return {
            "success": success,
            "message": message,
            "stats": self.stats.copy()  # 返回统计信息的副本
        }

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
            #logger.info(f"默认保存目录已设置: '{DEFAULT_SAVE_DIR}' (ID: {self.default_save_dir_id})")
        
        for base_dir in EXPORT_BASE_DIRS:
            base_dir_id = self.get_or_create_directory(base_dir)
            self.export_base_dir_ids.append(base_dir_id)
            self.export_base_dir_map[base_dir_id] = base_dir
            #logger.info(f"导出基目录已设置: '{base_dir}' (ID: {base_dir_id})")
        
        self.search_max_depth = SEARCH_MAX_DEPTH
        #logger.info(f"搜索最大深度已设置: {self.search_max_depth} 层")
        
        # 初始化目录缓存
        self.directory_cache = {}
        self.load_directory_cache()
        #logger.info(f"已加载 {len(self.directory_cache)} 个目录缓存")
    
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
                #logger.info(f"已加载 {len(rows)} 个目录缓存")
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

    def get_share_info_by_folder_name(self, folder_name):
        """根据文件夹名称获取分享信息（分页查询）"""
        if not self.token_manager.ensure_token_valid():
            return None
            
        last_share_id = 0
        headers = self.token_manager.get_auth_header()
        
        while True:
            url = f"{OPEN_API_HOST}{API_PATHS['LIST_SHARE']}"
            params = {
                "limit": 100,
                "lastShareId": last_share_id
            }
            
            try:
                response = self._call_api("GET", url, params=params, headers=headers, timeout=30)
                if not response or response.status_code != 200:
                    return None
                    
                data = response.json()
                if data.get("code") != 0:
                    return None
                
                # 检查当前页的分享列表
                for share in data["data"].get("shareList", []):
                    # 检查分享是否包含目标文件夹且未失效
                    if (share["shareName"] == (folder_name) and \
                       share["expired"] == 0 ):
                        return share
                
                # 检查是否还有下一页
                last_share_id = data["data"].get("lastShareId", -1)
                if last_share_id == -1:
                    break
                    
            except Exception as e:
                logger.error(f"查询分享列表出错: {e}")
                return None
                
        return None

    def create_share_link(self, file_id, folder_name, expire_days=0):
        """创建分享链接（使用预设提取码）"""
        try:
            url = f"{OPEN_API_HOST}{API_PATHS['CREATE_SHARE']}"
            headers = self.token_manager.get_auth_header()
            
            payload = {
                "shareName": folder_name,
                "shareExpire": expire_days,  # 0=永久
                "fileIDList": str(file_id),
                "sharePwd": DEFAULT_SHARE_PASSWORD,  # 使用预设提取码
                "trafficSwitch": 1,  # 关闭免登录流量包
                "trafficLimitSwitch": 1  # 关闭流量限制
            }
            
            response = self._call_api("POST", url, json=payload, headers=headers, timeout=30)
            if not response or response.status_code != 200:
                return None, None
                
            data = response.json()
            if data.get("code") != 0:
                return None, None
                
            share_key = data["data"].get("shareKey")
            return share_key, DEFAULT_SHARE_PASSWORD  # 返回预设提取码
        except Exception as e:
            logger.error(f"创建分享链接失败: {e}")
            return None, None

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
    def __init__(self, token, pan_client, allowed_user_ids, transfer_service):
        self.token = token
        self.pan_client = pan_client
        self.transfer = transfer_service
        self.allowed_user_ids = allowed_user_ids
        self.updater = Updater(token, use_context=True)
        self.dispatcher = self.updater.dispatcher
        self.start_time = pan_client.token_manager.start_time
        
        # 注册处理程序
        self.dispatcher.add_handler(CommandHandler("start", self.start_command))
        self.dispatcher.add_handler(CommandHandler("export", self.export_command))
        self.dispatcher.add_handler(CommandHandler("sync_full", self.sync_full_command))
        self.dispatcher.add_handler(CommandHandler("strm", self.strm_command))  # 新增STRM命令
        self.dispatcher.add_handler(CommandHandler("search", self.search_command))
        self.dispatcher.add_handler(CommandHandler("restore", self.restore_command))
        self.dispatcher.add_handler(CommandHandler("clear_trash", self.clear_trash_command))
        self.dispatcher.add_handler(CommandHandler("add", self.add_command))
        self.dispatcher.add_handler(CommandHandler("delete", self.delete_command))
        self.dispatcher.add_handler(CommandHandler("info", self.info_command))
        self.dispatcher.add_handler(CommandHandler("refresh_token", self.refresh_token_command))
        self.dispatcher.add_handler(CommandHandler("transport", self.transport_command))  # 新增transport命令
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
            BotCommand("strm", "生成STRM"),
            BotCommand("search", "生成STRM"),
            BotCommand("sync_full", "全量同步"),
            BotCommand("transport", "迁移115文件"),
            BotCommand("restore", "恢复STRM"),
            BotCommand("clear_trash", "清空123回收站"),
            BotCommand("refresh_token", "强制刷新Token"),
            BotCommand("info", "用户信息"),
            BotCommand("add", "添加用户"),
            BotCommand("delete", "删除用户"),            
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

            media_stats = get_media_library_stats()
            
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
                f"🎬 <b>媒体库统计</b>\n"
                f"├ 电影: {media_stats['movie_count']}部 ({format_size(media_stats['movie_size'])})\n"
                f"├ 电视剧: {media_stats['tv_count']}部 ({format_size(media_stats['tv_size'])})\n"
                f"├ 字幕文件: {media_stats['sub_count']}个 ({format_size(media_stats['sub_size'])})\n"
                f"└ 文件总数: {media_stats['total_count']}个 ({format_size(media_stats['total_size'])})\n\n"
                f"⚙️ <b>当前配置:</b>\n"
                f"├ 保存目录: <code>{DEFAULT_SAVE_DIR or '根目录'}</code>\n"
                f"├ 导出目录: <code>{', '.join(EXPORT_BASE_DIRS) if EXPORT_BASE_DIRS else '根目录'}</code>\n"
                f"├ 搜索深度: <code>{SEARCH_MAX_DEPTH}层</code>\n"
                f"└ 数据缓存: <code>{len(self.pan_client.directory_cache)}</code>\n\n"
                f"🤖 <b>机器人控制中心</b>\n"
                f"▫️ /export - 导出文件\n"
                f"▫️ /strm - 生成STRM\n"
                f"▫️ /restore - 从数据库恢复STRM\n"
                f"▫️ /search - 搜索媒体库\n"
                f"▫️ /sync_full - 全量同步\n"                                           
                f"▫️ /clear_trash - 清空回收站\n"
                f"▫️ /transport - 迁移115文件\n\n"   # 新增
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
        """处理选择的导出任务（使用后台线程）"""
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
        
        # 获取选中的文件夹信息
        selected_folders = [results[idx] for idx in selected_indices]
        
        # 启动后台线程执行导出
        threading.Thread(
            target=self.export_folders,
            args=(
                context.bot,
                query.message.chat_id,
                user_id,
                selected_folders,
                in_group,
                context.user_data.get('group_chat_id') if in_group else None
            ),
            daemon=True
        ).start()
        
        # 更新用户导出次数
        self.update_user_export_count(user_id, folder_count)
        
        # 清理上下文
        self.cleanup_export_context(context.user_data)
    
    def export_folders(self, bot, chat_id, user_id, folders, is_group=False, group_chat_id=None):
        """在后台线程中导出文件夹"""
        total = len(folders)
        progress_messages = []
        
        # 每处理一个文件夹发送一个进度消息（最多10条）
        for i, folder_info in enumerate(folders):
            # 每3个文件夹发送一次进度
            if i % 3 == 0:
                try:
                    msg_text = f"⏳ 正在处理文件夹 [{i+1}/{total}]:\n├ 名称: {folder_info['filename']}\n└ 路径: {folder_info['full_path']}"
                    if is_group and PRIVATE_EXPORT:
                        # 在群聊中且设置私聊发送，则发到用户私聊
                        msg = bot.send_message(chat_id=user_id, text=msg_text)
                    else:
                        # 否则发到原聊天
                        target_chat_id = group_chat_id if is_group else chat_id
                        msg = bot.send_message(chat_id=target_chat_id, text=msg_text)
                    progress_messages.append(msg.message_id)
                except Exception as e:
                    logger.error(f"发送进度消息失败: {e}")
            
            # 处理单个文件夹
            self._export_single_folder(bot, folder_info, user_id, is_group, group_chat_id)
        
        # 导出完成后删除所有进度消息
        for msg_id in progress_messages:
            try:
                if is_group and PRIVATE_EXPORT:
                    bot.delete_message(chat_id=user_id, message_id=msg_id)
                else:
                    target_chat_id = group_chat_id if is_group else chat_id
                    bot.delete_message(chat_id=target_chat_id, message_id=msg_id)
            except Exception as e:
                logger.warning(f"删除进度消息失败: {e}")
        
        # 发送完成通知
        completion_msg = f"✅ 导出完成！共处理 {total} 个文件夹"
        if is_group and PRIVATE_EXPORT:
            bot.send_message(chat_id=user_id, text=completion_msg)
        else:
            target_chat_id = group_chat_id if is_group else chat_id
            bot.send_message(chat_id=target_chat_id, text=completion_msg)
    
    def _export_single_folder(self, bot, folder_info, user_id, is_group, group_chat_id):
        """导出单个文件夹（线程安全）"""
        folder_id = folder_info["file_id"]
        folder_name = folder_info["filename"]
        folder_path = folder_info["full_path"]
        
        files = self.pan_client.get_directory_files(folder_id, folder_name)
        if not files:
            logger.warning(f"文件夹为空: {folder_name}")
            return
            
        # 清理文件夹名称（移除非法字符）
        clean_folder_name = re.sub(r'[\\/*?:"<>|]', "", folder_name)
        # 在文件夹名称后添加斜杠
        common_path = f"{clean_folder_name}/"
        # 文件名保持原始格式（不带斜杠）
        file_name = f"{clean_folder_name}.json"
        
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

        # 先尝试获取现有分享链接
        share_info = self.pan_client.get_share_info_by_folder_name(folder_name)
        if share_info and share_info["expired"] == 0:
            # 使用现有分享链接
            share_key = share_info["shareKey"]
            share_pwd = share_info["sharePwd"]
            logger.info(f"使用现有分享链接: {folder_name} (ID: {folder_id})")
        else:
            # 创建新分享链接
            share_key, share_pwd = self.pan_client.create_share_link(folder_id, clean_folder_name)
            if share_key:
                logger.info(f"创建新分享链接: {folder_name} (ID: {folder_id})")
        
        caption = (             
            f"✨ 分享者：{nickname}\n"
            f"📁 文件名: {clean_folder_name}\n"
            f"📝 文件数: {file_count}\n"
            f"💾 总大小：{format_size(total_size)}\n"
            f"📊 平均大小：{format_size(avg_size)}\n"
        )
        # 如果有分享链接则添加
        if share_key:
            caption += (
                f"🔗 分享链接：https://www.123pan.com/s/{share_key}?提取码:{share_pwd}\n\n"
                f"❤️ 123因您分享更完美！"
            )
        else:
            caption += (
                f"⚠️ 此片你懂的😍，未能创建分享链接\n\n"
                f"❤️ 123因您分享更完美！"
            )
        
        # 发送文件
        try:
            with open(file_name, "rb") as f:
                if is_group and PRIVATE_EXPORT:
                    # 群聊且设置私聊发送，则发送到用户私聊
                    bot.send_document(
                        chat_id=user_id,
                        document=f,
                        filename=file_name,
                        caption=caption
                    )
                else:
                    # 否则发送到原聊天
                    target_chat_id = group_chat_id if is_group else user_id
                    bot.send_document(
                        chat_id=target_chat_id,
                        document=f,
                        filename=file_name,
                        caption=caption
                    )
        except Exception as e:
            logger.error(f"发送文件失败: {e}")
        finally:
            # 删除临时文件
            try:
                os.remove(file_name)
            except Exception:
                pass
 
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
        # 添加迁移状态查询处理
        elif data.startswith("transport_status_"):
            task_id = data.split("_", 2)[2]
            self.get_transport_status(update, context, task_id)

    def send_transport_status(self, update: Update, context: CallbackContext, task_id):
        """发送迁移状态消息"""
        # 获取任务状态
        with self.transfer.lock:
            task = self.transfer.active_transfers.get(task_id)
            if not task:
                context.bot.send_message(
                    chat_id=update.message.chat_id,
                    text=f"❌ 迁移任务 {task_id} 不存在或已过期"
                )
                return
            # 构建状态消息
            stats = task["stats_ref"]
            status_msg = self._build_transport_status_message(task_id, task, stats)
            # 创建刷新按钮
            keyboard = [[
                InlineKeyboardButton("🔄 刷新状态", callback_data=f"transport_status_{task_id}")
            ]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            # 发送消息
            context.bot.send_message(
                chat_id=update.message.chat_id,
                text=status_msg,
                reply_markup=reply_markup
            )

    def _build_transport_status_message(self, task_id, task, stats):
        """构建迁移状态消息"""
        # 获取实时统计信息
        elapsed_time = time.time() - task['start_time']
        # 生成唯一标识符防止消息未修改错误
        unique_id = int(time.time())
        # 构建状态消息
        status_msg = (
            f"⏳ 迁移任务进行中 (ID: {task_id})\n"
            f"├ 已运行: {format_time(elapsed_time)}\n"
            f"├ 扫描文件数: {stats.get('total_files', 0)}\n"
            f"├ 需提交迁移: {stats.get('to_transfer_files', 0)}\n"
            f"├ 成功: {stats.get('success_count', 0)}\n"
            f"└ 失败: {stats.get('fail_count', 0)}\n"
            f"├ 总大小: {format_size(stats.get('total_size', 0))}\n"
            f"└ 迁移大小: {format_size(stats.get('transfer_size', 0))}\n"
            f"🔁 刷新ID: {unique_id}"
        )
        return status_msg

    def get_transport_status(self, update: Update, context: CallbackContext, task_id):
        """获取迁移任务状态 - 任务完成后自动显示完整报告"""
        try:
            # 获取任务状态
            with self.transfer.lock:
                task = self.transfer.active_transfers.get(task_id)
            
            if not task:
                # 尝试发送任务不存在的消息
                try:
                    update.callback_query.edit_message_text(
                        f"❌ 迁移任务 {task_id} 已完成或已过期"
                    )
                except Exception:
                    pass
                return
                
            if task["status"] == "running":
                # 获取实时统计信息
                stats = task["stats_ref"]
                # 构建状态消息
                status_msg = self._build_transport_status_message(task_id, task, stats)
                # 更新按钮保持可刷新
                keyboard = [[
                    InlineKeyboardButton("🔄 刷新状态", callback_data=f"transport_status_{task_id}")
                ]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                # 尝试更新消息
                try:
                    context.bot.edit_message_text(
                        chat_id=update.callback_query.message.chat_id,
                        message_id=update.callback_query.message.message_id,
                        text=status_msg,
                        reply_markup=reply_markup
                    )
                except Exception as e:
                    # 忽略所有错误，因为可能是状态没有变化
                    logger.debug(f"状态更新可能无变化: {e}")
            else:
                # 任务已完成 - 显示完整报告
                result = task.get("result", {})
                stats = result.get("stats", {})
                elapsed_time = stats.get("elapsed_time", 0)
                report = self._build_transfer_report(stats, elapsed_time)
                
                # 任务完成后，显示完整报告并移除按钮
                final_message = f"✅ 115迁移任务已完成 (ID: {task_id})\n\n{report}"
                try:
                    context.bot.edit_message_text(
                        chat_id=update.callback_query.message.chat_id,
                        message_id=update.callback_query.message.message_id,
                        text=final_message
                    )
                    
                    # 任务完成后保留一段时间（10分钟）再删除
                    def cleanup_task():
                        time.sleep(600)  # 10分钟后清理
                        with self.transfer.lock:
                            if task_id in self.transfer.active_transfers:
                                del self.transfer.active_transfers[task_id]
                    
                    threading.Thread(target=cleanup_task, daemon=True).start()
                except Exception as e:
                    logger.error(f"更新最终报告失败: {e}")
        except Exception as e:
            logger.error(f"获取迁移状态时出错: {e}")
            try:
                update.callback_query.edit_message_text(
                    f"❌ 获取迁移状态时出错: {str(e)}"
                )
            except:
                pass

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
    def process_115_share(self, update: Update, context: CallbackContext, share_link):
        """处理115分享链接迁移"""
        try:
            user_id = update.message.from_user.id
            # 启动迁移任务
            task_id = self.transfer.migrate(share_link, user_id=user_id)
            # 直接发送迁移状态消息
            self.send_transport_status(update, context, task_id)
        except Exception as e:
            logger.error(f"处理115分享链接失败: {e}")
            self.send_auto_delete_message(update, context, f"❌ 处理115分享链接失败: {e}")
    
    def _build_transfer_report(self, stats, elapsed_time):
        """构建迁移统计报告"""
        report = (
            f"📊 115迁移统计报告\n"
            f"══════════════════════\n"
            f"📂 扫描文件总数: {stats.get('total_files', 0)} (大小: {format_size(stats.get('total_size', 0))})\n"
            f"🚫 过滤文件数: {stats.get('filtered_files', 0)} (大小: {format_size(stats.get('filtered_size', 0))})\n"
            f"📤 提交迁移文件数: {stats.get('to_transfer_files', 0)} (大小: {format_size(stats.get('transfer_size', 0))})\n"
            f"✅ 成功提交文件数: {stats.get('success_count', 0)}\n"
            f"❌ 提交失败文件数: {stats.get('fail_count', 0)}\n"
            f"⏱️ 总耗时: {format_time(elapsed_time)}\n"
            f"══════════════════════"
        )
        
        # 添加失败文件列表（如果有）
        failed_files = stats.get("failed_files", [])
        if failed_files:
            report += f"\n\n❌ 失败文件列表:\n" + "\n".join([f"- {name}" for name in failed_files[:10]])
            if len(failed_files) > 10:
                report += f"\n...及其他 {len(failed_files) - 10} 个文件"
        
        return report

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
        elif re.match(r"https?://115(?:cdn)?\.com/s/\w+\?password=\w+", text):
            self.send_auto_delete_message(update, context, "🔗 检测到115分享链接，开始迁移...")
            self.process_115_share(update, context, text)
    
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
        """处理/transport命令 - 迁移115文件（后台运行）"""
        try:
            user_id = update.message.from_user.id
            task_id = self.transfer.migrate(user_id=user_id)
            # 直接发送迁移状态消息
            self.send_transport_status(update, context, task_id)
        except Exception as e:
            logger.error(f"启动迁移任务失败: {e}")
            self.send_auto_delete_message(update, context, f"❌ 启动迁移任务失败: {e}")


    @admin_required
    def strm_command(self, update: Update, context: CallbackContext):
        """处理/strm命令 - 高效生成STRM文件"""
        self.send_auto_delete_message(update, context, "⏳ 正在快速生成视频STRM文件，请稍候...")
        logger.info("开始高效生成视频STRM文件...")
        
        try:
            # 确保输出目录存在
            os.makedirs(STRM_OUTPUT_DIR, exist_ok=True)
            # 创建STRM生成器实例
            strm_generator = STRMGenerator()
            strm_generator.pan_client = self.pan_client  # 注入pan_client依赖
            
            total_generated = 0
            start_time = time.time()
            # 并行处理所有媒体库目录
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                for base_dir_id in self.pan_client.export_base_dir_ids:
                    base_dir_name = self.pan_client.export_base_dir_map.get(base_dir_id, str(base_dir_id))
                    futures.append(executor.submit(
                        strm_generator.generate_strm_files_recursive,  # 使用正确的实例方法
                        base_dir_id, 
                        base_dir_name,
                        base_dir_name  # 作为前缀移除
                    ))
                for future in as_completed(futures):
                    count = future.result()
                    total_generated += count
                    logger.info(f"媒体库目录处理完成，生成 {count} 个视频STRM文件")
            elapsed = time.time() - start_time
            message = (
                f"✅ 视频STRM文件生成完成！\n"
                f"├ 共生成 {total_generated} 个文件\n"
                f"├ 保存位置: {STRM_OUTPUT_DIR}\n"
                f"└ 总耗时: {elapsed:.2f}秒"
            )
            update.message.reply_text(message)
            logger.info(f"STRM高效生成任务完成，总计 {total_generated} 个视频文件，耗时 {elapsed:.2f}秒")        
        except Exception as e:
            logger.error(f"生成STRM文件失败: {e}")
            self.send_auto_delete_message(update, context, f"❌ 生成STRM文件失败: {str(e)}")

    @admin_required
    def restore_command(self, update: Update, context: CallbackContext):
        """处理/restore命令 - 从数据库恢复STRM和字幕文件"""
        self.send_auto_delete_message(update, context, "⏳ 正在从数据库恢复STRM和字幕文件...")
        
        # 在后台线程中执行恢复
        def do_restore():
            try:
                strm_generator = STRMGenerator()
                strm_generator.pan_client = self.pan_client
                result = strm_generator.restore_strm_files_from_db()
                context.bot.send_message(chat_id=update.message.chat_id, text=result)
            except Exception as e:
                logger.error(f"恢复失败: {e}")
                context.bot.send_message(
                    chat_id=update.message.chat_id,
                    text=f"❌ 恢复失败: {str(e)}"
                )
        
        threading.Thread(target=do_restore, daemon=True).start()
    
    def search_command(self, update: Update, context: CallbackContext):
        """处理/search命令"""
        keyword = " ".join(context.args) if context.args else ""
        
        if not keyword:
            self.send_auto_delete_message(update, context, "❌ 请指定搜索关键字！格式: /search <关键字>")
            return
        
        # 保存搜索关键字
        context.user_data['search_keyword'] = keyword
        context.user_data['search_page'] = 0
        context.user_data['search_results'] = []
        
        # 执行搜索
        strm_generator = STRMGenerator()
        results = strm_generator.search_media(keyword)
        
        if not results:
            self.send_auto_delete_message(update, context, f"❌ 未找到包含 '{keyword}' 的媒体资源")
            return
        
        context.user_data['search_results'] = results
        self.show_search_results(update, context)
    
    def show_search_results(self, update: Update, context: CallbackContext):
        """显示搜索结果（分页）"""
        results = context.user_data.get('search_results', [])
        page = context.user_data.get('search_page', 0)
        keyword = context.user_data.get('search_keyword', '')
        
        if not results:
            return
        
        total_pages = (len(results) + 5) // 6  # 每页6个结果
        start_idx = page * 6
        end_idx = min((page + 1) * 6, len(results))
        page_results = results[start_idx:end_idx]
        
        # 创建结果键盘
        keyboard = []
        for i, result in enumerate(page_results):
            idx = start_idx + i
            display_name = result["media_name"]
            if len(display_name) > 20:
                display_name = display_name[:17] + "..."
                
            keyboard.append([
                InlineKeyboardButton(
                    f"{idx+1}. {display_name} ({result['media_type']})", 
                    callback_data=f"search_select_{idx}"
                )
            ])
        
        # 添加分页按钮
        page_buttons = []
        if page > 0:
            page_buttons.append(InlineKeyboardButton("⬅️ 上一页", callback_data="search_prev"))
        if page < total_pages - 1:
            page_buttons.append(InlineKeyboardButton("➡️ 下一页", callback_data="search_next"))
        
        if page_buttons:
            keyboard.append(page_buttons)
        
        # 添加取消按钮
        keyboard.append([InlineKeyboardButton("❌ 取消", callback_data="search_cancel")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # 发送或更新消息
        message_text = (
            f"🔍 搜索 '{keyword}' 结果 (第 {page+1}/{total_pages} 页)\n"
            f"找到 {len(results)} 个匹配的媒体资源:"
        )

        if update.callback_query:
            chat_id = update.callback_query.message.chat_id
        else:
            chat_id = update.message.chat_id  # 普通消息场景
        
        if 'search_message_id' in context.user_data:
            try:
                context.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=context.user_data['search_message_id'],
                    text=message_text,
                    reply_markup=reply_markup
                )
            except BadRequest:
                # 消息内容未变化，忽略错误
                pass
        else:
            msg = update.message.reply_text(message_text, reply_markup=reply_markup)
            context.user_data['search_message_id'] = msg.message_id
        
        # 设置超时任务
        self.set_search_timeout(context, chat_id) 
    
    def set_search_timeout(self, context, chat_id):
        """设置搜索超时任务"""
        # 取消现有任务
        if 'search_timeout_job' in context.user_data:
            context.user_data['search_timeout_job'].schedule_removal()
        
        # 创建新任务
        job = context.job_queue.run_once(
            self.search_timeout, 
            120,  # 2分钟后超时
            context=chat_id,
            name=f"search_timeout_{chat_id}"
        )
        context.user_data['search_timeout_job'] = job
    
    def search_timeout(self, context):
        """搜索超时处理"""
        if context is None or context.user_data is None:
            logger.warning("search_timeout: context or user_data is None, skipping cleanup")
            return
        
        # 清除搜索状态
        if 'search_message_id' in context.user_data:
            try:
                context.bot.edit_message_text(
                    chat_id=context.job.context,
                    message_id=context.user_data['search_message_id'],
                    text="⏱️ 搜索会话已超时关闭"
                )
            except Exception:
                pass
        
        # 清理用户数据
        keys = ['search_keyword', 'search_page', 'search_results', 'search_message_id', 'selected_media']
        for key in keys:
            if key in context.user_data:
                del context.user_data[key]
    
    def show_media_details(self, update: Update, context: CallbackContext, result_idx):
        """显示媒体详细信息"""
        results = context.user_data.get('search_results', [])
        if result_idx < 0 or result_idx >= len(results):
            return
        
        media_info = results[result_idx]
        context.user_data['selected_media'] = media_info
        
        # 构建信息消息
        message = (
            f"🎬 媒体详情\n"
            f"══════════════════════\n"
            f"📛 名称: {media_info['media_name']}\n"
            f"📁 类型: {media_info['media_type'].upper()}\n"
            f"📊 文件数: {media_info['file_count']}\n"
            f"💾 总大小: {format_size(media_info['total_size'])}\n"
            f"📂 本地路径: {media_info['sample_path'] or '无'}\n"
            f"══════════════════════"
        )
        
        # 创建操作按钮
        keyboard = [
            [
                InlineKeyboardButton("🗑️ 删除", callback_data="media_delete"),
                InlineKeyboardButton("📥 导出JSON", callback_data="media_export")
            ],
            [InlineKeyboardButton("🔙 返回", callback_data="media_back")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # 发送或更新消息
        try:
            context.bot.edit_message_text(
                chat_id=update.callback_query.message.chat_id,
                message_id=context.user_data['search_message_id'],
                text=message,
                reply_markup=reply_markup
            )
        except BadRequest:
            pass
        
        # 重置超时时间
        self.set_search_timeout(context, update.callback_query.message.chat_id)
    
    def button_callback(self, update: Update, context: CallbackContext):
        """处理按钮回调"""
        query = update.callback_query
        query.answer()
        data = query.data
        
        if context.user_data is None:
            logger.warning("Button callback received with no user_data")
            return
        
        # 搜索相关回调
        if data.startswith("search_"):
            if data == "search_prev":
                context.user_data['search_page'] = max(0, context.user_data.get('search_page', 0) - 1)
                self.show_search_results(update, context)
            elif data == "search_next":
                context.user_data['search_page'] = context.user_data.get('search_page', 0) + 1
                self.show_search_results(update, context)
            elif data == "search_cancel":
                query.edit_message_text("❌ 搜索已取消")
                self.cleanup_search_context(context.user_data)
            elif data.startswith("search_select_"):
                try:
                    result_idx = int(data.split("_")[2])
                    self.show_media_details(update, context, result_idx)
                except (ValueError, IndexError):
                    pass
        
        # 媒体操作回调
        elif data.startswith("media_"):
            media_info = context.user_data.get('selected_media', {})
            media_name = media_info.get('media_name', '')
            
            if data == "media_delete":
                self.delete_media(update, context, media_name)
            elif data == "media_export":
                self.export_media(update, context, media_name)
            elif data == "media_back":
                self.show_search_results(update, context)
    
    def delete_media(self, update: Update, context: CallbackContext, media_name):
        """删除媒体"""
        strm_generator = STRMGenerator()
        deleted_count = strm_generator.delete_media(media_name)
        
        if deleted_count > 0:
            message = f"✅ 已删除媒体 '{media_name}'\n共移除 {deleted_count} 条记录"
            # 从搜索结果中移除
            results = context.user_data.get('search_results', [])
            context.user_data['search_results'] = [r for r in results if r['media_name'] != media_name]
        else:
            message = f"❌ 删除媒体 '{media_name}' 失败"
        
        try:
            context.bot.edit_message_text(
                chat_id=update.callback_query.message.chat_id,
                message_id=context.user_data['search_message_id'],
                text=message
            )
        except BadRequest:
            pass
        
        # 清理上下文
        if 'selected_media' in context.user_data:
            del context.user_data['selected_media']
        
        # 设置5秒后返回搜索结果
        context.job_queue.run_once(
            lambda ctx: self.show_search_results(update, context), 
            5, 
            name="return_to_search"
        )
    
    def export_media(self, update: Update, context: CallbackContext, media_name):
        """导出媒体JSON"""
        strm_generator = STRMGenerator()
        json_file = strm_generator.export_media_json(media_name)
        
        if json_file:
            try:
                with open(json_file, "rb") as f:
                    context.bot.send_document(
                        chat_id=update.callback_query.message.chat_id,
                        document=f,
                        filename=os.path.basename(json_file),
                        caption=f"📥 媒体 '{media_name}' 的JSON导出文件"
                    )
                # 删除临时文件
                os.remove(json_file)
            except Exception as e:
                logger.error(f"发送JSON文件失败: {e}")
        else:
            try:
                context.bot.edit_message_text(
                    chat_id=update.callback_query.message.chat_id,
                    message_id=context.user_data['search_message_id'],
                    text=f"❌ 导出媒体 '{media_name}' 失败"
                )
            except BadRequest:
                pass
    
    def cleanup_search_context(self, user_data: dict):
        """清理搜索相关的上下文数据"""
        keys = ['search_keyword', 'search_page', 'search_results', 
                'search_message_id', 'selected_media', 'search_timeout_job']
        for key in keys:
            if key in user_data:
                del user_data[key]
    
def main():
    # 添加授权信息提示
    logger.info("=============================================")
    logger.info("123云盘机器人 - 开心版")
    logger.info(f"版本: {VERSION}")
    logger.info("=============================================")

    logger.info("初始化123云盘客户端...")
    pan_client = Pan123Client(CLIENT_ID, CLIENT_SECRET)
    
    if not pan_client.token_manager.access_token:
        logger.error("❌ 无法获取有效的Token")
        return
    
    # 创建Pan123API实例
    pan123_api = Pan123API(pan_client.token_manager)
    
    # 创建115迁移服务
    transfer_service = Pan115to123Transfer(
        p115_cookie=P115_COOKIE,
        target_cid=TARGET_CID,
        user_agent=USER_AGENT,
        pan123_api=pan123_api,
        allowed_extensions=ALLOWED_EXTENSIONS
    )
    
    logger.info("初始化Telegram机器人...")
    bot_handler = TelegramBotHandler(
        token=BOT_TOKEN,
        pan_client=pan_client,
        transfer_service=transfer_service,
        allowed_user_ids=ADMIN_USER_IDS
    )
    bot_handler.start()

if __name__ == "__main__":
    main()
