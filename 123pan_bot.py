import warnings

warnings.filterwarnings("ignore", message="python-telegram-bot is using upstream urllib3.*")

warnings.filterwarnings("ignore", message=".*pkg_resources is deprecated.*", category=UserWarning)
import os
import re
import json
import time
import logging
import requests
from datetime import datetime, timedelta, timezone
from telegram import Update
from telegram.ext import Updater, MessageHandler, Filters, CallbackContext, CommandHandler
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

# 123云盘API配置
PAN_HOST = "https://www.123pan.com"
API_PATHS = {
    "TOKEN": "/api/v1/access_token",
    "LIST_FILES_V2": "/api/v2/file/list",  # 获取文件列表V2
    "FILE_INFOS": "/api/v1/file/infos",    # 批量获取文件信息
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

class TokenManager:
    """管理API token的获取和缓存"""
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret
        self.session = self._create_session()
        self.access_token = None
        self.token_expiry = None
    
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
            
            logger.info(f"更新Token\n└─有效期至: {self.token_expiry} (UTC)")
            return True
            
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
    
    def search_folder_recursive(self, folder_name, parent_id=0, current_path=""):
        """递归搜索整个云盘结构中的文件夹"""
        logger.info(f"搜索文件夹: '{folder_name}' (父ID: {parent_id}, 当前路径: '{current_path}')")
        
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
                        return {
                            "fileId": item["fileId"],
                            "filename": item["filename"],
                            "path": item_path
                        }
                    
                    # 递归搜索子目录
                    time.sleep(0.5)  # 增加延迟避免限流
                    found_folder = self.search_folder_recursive(
                        folder_name,
                        item["fileId"],
                        item_path
                    )
                    if found_folder:
                        return found_folder
                
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
        
        # 注册处理程序
        self.dispatcher.add_handler(CommandHandler("export", self.export_command))  # 添加导出命令
        self.dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, self.handle_text))
        self.dispatcher.add_handler(MessageHandler(Filters.document, self.handle_document))
    
    def start(self):
        """启动机器人"""
        self.updater.start_polling()
        logger.info("🤖 机器人已启动，等待消息...")
        logger.info(f"管理员用户ID: {self.allowed_user_ids}")
        self.updater.idle()
    
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
    
    @admin_required
    def handle_text(self, update: Update, context: CallbackContext):
        """处理文本消息（秒传链接）"""
        text = update.message.text.strip()
        
        # 检查是否是秒传链接
        if any(prefix in text for prefix in [
            LEGACY_FOLDER_LINK_PREFIX_V1,
            LEGACY_FOLDER_LINK_PREFIX_V2,
            COMMON_PATH_LINK_PREFIX_V1,
            COMMON_PATH_LINK_PREFIX_V2
        ]):
            logger.info(f"收到秒传链接: {text[:50]}...")
            update.message.reply_text("🔍 检测到秒传链接，开始解析...")
            self.process_fast_link(update, text)
    
    @admin_required
    def handle_document(self, update: Update, context: CallbackContext):
        """处理文档消息（JSON文件）"""
        document = update.message.document
        user_id = update.message.from_user.id
        file_name = document.file_name
        
        # 检查是否是JSON文件
        if document.mime_type != "application/json" and not file_name.endswith(".json"):
            update.message.reply_text("❌ 请发送JSON格式的文件！")
            return
        
        logger.info(f"收到JSON文件: {file_name}")
        update.message.reply_text("📥 收到JSON文件，开始下载并解析...")
        
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
            self.process_json_file(update, json_data)
        except Exception as e:
            logger.error(f"❌ 处理JSON文件出错: {str(e)}")
            update.message.reply_text(f"❌ 处理JSON文件时出错: {str(e)}")
    
    @admin_required
    def process_fast_link(self, update: Update, share_link):
        """处理秒传链接转存"""
        try:
            files = FastLinkProcessor.parse_share_link(share_link)
            if not files:
                logger.warning("无法解析秒传链接或链接中无有效文件信息")
                update.message.reply_text("❌ 无法解析秒传链接或链接中无有效文件信息")
                return
            
            logger.info(f"开始转存 {len(files)} 个文件...")
            update.message.reply_text(f"✅ 解析成功！找到 {len(files)} 个文件，开始转存...")
            
            # 转存文件
            results = self.transfer_files(update, files)
            
            # 发送结果
            self.send_transfer_results(update, results)
            
        except Exception as e:
            logger.error(f"❌ 处理秒传链接出错: {str(e)}")
            update.message.reply_text(f"❌ 处理秒传链接时出错: {str(e)}")
    
    @admin_required
    def process_json_file(self, update: Update, json_data):
        """处理JSON文件转存"""
        try:
            if not isinstance(json_data, dict) or not json_data.get("files"):
                logger.warning("JSON格式无效，缺少files字段")
                update.message.reply_text("❌ JSON格式无效，缺少files字段")
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
            update.message.reply_text(f"✅ 解析成功！找到 {len(files)} 个文件，开始转存...")
            
            # 转存文件
            results = self.transfer_files(update, files)
            
            # 发送结果
            self.send_transfer_results(update, results)
            
        except Exception as e:
            logger.error(f"❌ 处理JSON文件出错: {str(e)}")
            update.message.reply_text(f"❌ 处理JSON文件时出错: {str(e)}")
    
    
    def transfer_files(self, update: Update, files):
        """转存文件列表（带重试机制）"""
        logger.info(f"开始转存 {len(files)} 个文件...")
        results = []
        total_files = len(files)
        root_dir_id = "0"
        
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
    
    def send_transfer_results(self, update: Update, results):
        """发送转存结果，包含失败文件详情"""
        success_count = sum(1 for r in results if r["success"])
        failed_count = len(results) - success_count
        
        result_text = (
            f"📊 转存完成！\n"
            f"✅ 成功: {success_count}\n"
            f"❌ 失败: {failed_count}"
        )
        
        # 添加失败文件详情
        if failed_count > 0:
            failed_files = []
            for result in results:
                if not result["success"]:
                    # 简化文件名显示
                    file_name = result["file_name"]
                    if len(file_name) > 50:
                        file_name = f"...{file_name[-47:]}"
                    
                    failed_files.append(f"• {file_name}: {result['error']}")
            
            result_text += "\n\n❌ 失败文件:\n" + "\n".join(failed_files[:10])  # 最多显示10个失败文件
            
            if failed_count > 10:
                result_text += f"\n...及其他 {failed_count - 10} 个失败文件"
        
        update.message.reply_text(result_text)

    @admin_required
    def export_command(self, update: Update, context: CallbackContext):
        """处理/export命令，按名称导出文件夹为JSON"""
        logger.info("收到/export命令")
        
        # 获取命令参数（合并所有参数为文件夹名称）
        folder_name = " ".join(context.args) if context.args else ""
        
        if not folder_name:
            update.message.reply_text("❌ 请指定要导出的文件夹名称！格式: /export <文件夹名称>")
            return
        
        update.message.reply_text(f"🔍 正在全盘搜索文件夹: '{folder_name}'...")
        
        try:
            # 步骤1: 递归搜索文件夹
            folder_info = self.pan_client.search_folder_recursive(folder_name)
            if not folder_info:
                update.message.reply_text(f"❌ 未找到文件夹: '{folder_name}'")
                return
            
            folder_id = folder_info["fileId"]
            folder_path = folder_info.get("path", folder_name)
            
            # 提取搜索到的文件夹名称（最后一部分）
            folder_name_only = folder_path.split('/')[-1]
            update.message.reply_text(f"✅ 找到文件夹: '{folder_path}' (ID: {folder_id})，开始导出内容...")
            
            # 步骤2: 获取文件夹内容，保留完整子目录结构
            files = self.pan_client.get_directory_files(folder_id, folder_name_only)
            
            if not files:
                update.message.reply_text("⚠️ 该文件夹为空")
                return
            
            # 创建JSON结构，将搜索到的文件夹名称放在commonPath中
            json_data = {
                "commonPath": folder_name_only,  # 只存储搜索到的文件夹名称
                "usesBase62EtagsInExport": False,
                "files": [
                    {
                        "path": file_info["path"],  # 包含完整子目录结构
                        "etag": file_info["etag"],
                        "size": file_info["size"]
                    }
                    for file_info in files
                ]
            }
            
            # 清理文件夹名称（移除非法字符）
            clean_folder_name = re.sub(r'[\\/*?:"<>|]', "", folder_name_only)
            
            # 生成文件名（使用文件夹名称）
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_name = f"{clean_folder_name}_{timestamp}.json"
            
            # 保存为临时文件
            with open(file_name, "w", encoding="utf-8") as f:
                json.dump(json_data, f, ensure_ascii=False, indent=2)
            
            # 发送文件给用户
            with open(file_name, "rb") as f:
                update.message.reply_document(
                    document=f,
                    filename=file_name,
                    caption=f"✅ 导出完成！文件夹: '{folder_path}'\n共 {len(files)} 个文件\n将此文件发送回机器人可实现秒传"
                )
            
            # 删除临时文件
            os.remove(file_name)
            logger.info(f"已发送导出文件: {file_name}")
            
        except Exception as e:
            logger.error(f"导出文件夹失败: {str(e)}")
            update.message.reply_text(f"❌ 导出失败: {str(e)}")

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
    
    logger.info("初始化123云盘客户端...")
    pan_client = Pan123Client(CLIENT_ID, CLIENT_SECRET)
    
    logger.info("初始化Telegram机器人...")
    bot_handler = TelegramBotHandler(BOT_TOKEN, pan_client, ADMIN_USER_IDS)
    
    # 启动机器人
    logger.info("机器人启动中...")
    bot_handler.start()

if __name__ == "__main__":
    main()
