from flask import Flask, render_template, request, jsonify, Response, stream_with_context, session
import subprocess
import os
import logging
import sys
import io
from dotenv import load_dotenv
from auth import get_user_info_with_password
from werkzeug.serving import WSGIRequestHandler
from apscheduler.schedulers.background import BackgroundScheduler
import json
import time
from datetime import datetime
import sqlite3
from urllib.parse import unquote

# 加载环境变量
load_dotenv()

# 初始化 Flask 应用
app = Flask(__name__)
app.secret_key = os.urandom(24)

# 强制标准输出和错误输出使用 UTF-8 编码
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 配置日志（简化格式）
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler("web_strm.log", encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

# 自定义 SilentWSGIRequestHandler 以禁用 Werkzeug 日志
class SilentWSGIRequestHandler(WSGIRequestHandler):
    def log(self, type: str, message: str, *args) -> None:
        pass  # 完全禁用 Werkzeug 的日志输出

# 禁用 Flask 和 Werkzeug 的默认日志
logging.getLogger('werkzeug').disabled = True  # 禁用 Werkzeug 日志
logging.getLogger('flask.app').setLevel(logging.ERROR)  # 设置 Flask 日志级别为 ERROR

# 禁用 httpx 和 p123 的日志输出
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("p123").setLevel(logging.WARNING)  

# 115 配置文件路径
CONFIG115_PATH = os.getenv('CONFIG115_PATH', '/app/config/115_config.txt')
LOG115_PATH = os.getenv('LOG115_PATH', '/app/logs/115_auto.log')

# 初始化调度器
scheduler = BackgroundScheduler()
scheduler.start()


# DeepSeek 风格配色
DEEPSEEK_COLORS = {
    "primary": "#2d6ae3",
    "secondary": "#5b8def",
    "background": "#f8f9fa",
    "text": "#2d3846"
}

@app.route('/')
def index():
    """首页路由"""
    return render_template('index.html', colors=DEEPSEEK_COLORS)

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        passport = data.get('passport')
        password = data.get('password')
        
        # 调用验证接口
        user_info = get_user_info_with_password(passport, password)
        if user_info.get("code") != 0:
            return jsonify({"success": False, "message": user_info.get("message", "登录失败")})

        # 存储用户信息到session
        session['logged_in'] = True
        session['user_info'] = {
            'uid': user_info['data']['uid'],
            'nickname': user_info['data']['nickname'],
            'passport': user_info['data']['passport'],
            'spaceUsed': user_info['data']['spaceUsed'],
            'spacePermanent': user_info['data']['spacePermanent']
        }
        return jsonify({"success": True})
    except Exception as e:
        logging.error(f"登录失败: {str(e)}")
        return jsonify({"success": False, "message": "服务器错误"})

@app.route('/logout')
def logout():
    session.clear()
    return jsonify({"success": True})

@app.route('/user_info')
def get_user_info():
    if not session.get('logged_in'):
        return jsonify({"logged_in": False})
    return jsonify({
        "logged_in": True,
        "user_info": session['user_info']
    })

@app.route('/generate', methods=['GET'])
def generate_strm():
    """生成 STRM 文件的路由"""
    try:
        # 检查用户是否登录
        if not session.get('logged_in'):
            def generate_error():
                yield "event: error\ndata: 请先登录\n\n"
                yield "event: close\ndata: \n\n"
            return Response(stream_with_context(generate_error()), content_type='text/event-stream')

        # 从 session 中获取用户凭证
        user_info = session.get('user_info', {})
        p123_user = user_info.get('passport', '')
        p123_pass = request.args.get('p123_pass', '')  # 实际应从加密参数解析

        # 验证凭证有效性
        if not p123_user or not p123_pass:
            def generate_error():
                yield "event: error\ndata: 凭证无效\n\n"
                yield "event: close\ndata: \n\n"
            return Response(stream_with_context(generate_error()), content_type='text/event-stream')

        # 获取 URL 参数
        config_params = {
            'parent_id': request.args.get('parent_id', '0'),
            'local_path': request.args.get('local_path', './EmbyLibrary'),
            'video_exts': request.args.get('video_exts', '.mp4,.mkv,.avi'),
            'subtitle_exts': request.args.get('subtitle_exts', '.srt,.ass'),
            'request_delay': request.args.get('request_delay', '1'),
            'dir_delay': request.args.get('dir_delay', '2'),
            'timeout': request.args.get('timeout', '30'),
            'max_retries': request.args.get('max_retries', '3'),
            'direct_link_url': request.args.get('direct_link_url', 'http://172.17.0.1:8123')
        }

        # 构造环境变量
        env = os.environ.copy()
        env.update({
            'P123_USER': p123_user,
            'P123_PASS': p123_pass,
            'PARENT_ID': config_params['parent_id'],
            'LIBRARY_PATH': config_params['local_path'],
            'VIDEO_EXTS': config_params['video_exts'],
            'SUBTITLE_EXTS': config_params['subtitle_exts'],
            'REQUEST_DELAY': config_params['request_delay'],
            'DIR_DELAY': config_params['dir_delay'],
            'TIMEOUT': config_params['timeout'],
            'MAX_RETRIES': config_params['max_retries'],
            'DIRECT_LINK_URL': config_params['direct_link_url']
        })

        # 生成器函数，用于流式输出日志
        def generate():
            try:
                process = subprocess.Popen(
                    ['python', 'generate_strm.py'],
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,  # 将 stderr 合并到 stdout
                    text=True,
                    encoding='utf-8'
                )

                for line in iter(process.stdout.readline, ''):
                    yield f"data: {line}\n\n"
                process.stdout.close()
                return_code = process.wait()
                yield f"data: PROCESS_EXIT_CODE:{return_code}\n\n"  # 发送退出码
                yield "event: close\ndata: \n\n"  # 发送关闭事件
            except Exception as e:
                yield f"event: error\ndata: 子进程启动失败: {str(e)}\n\n"
                yield "event: close\ndata: \n\n"

        # 返回 SSE 响应
        return Response(stream_with_context(generate()), content_type='text/event-stream')

    except Exception as e:
        logging.error(f"[ERROR] 生成失败: {str(e)}")
        def generate_error():
            yield f"event: error\ndata: 生成失败: {str(e)}\n\n"
            yield "event: close\ndata: \n\n"
        return Response(stream_with_context(generate_error()), content_type='text/event-stream')
        
############115配置路由
def parse_115_config(content: str) -> dict:
    """增强版配置解析，支持紧凑格式"""
    config = {"main": None, "subs": []}
    current_section = None
    buffer = []

    lines = content.split('\n')
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        # 检测配置段
        if line.lower().startswith('main:'):
            current_section = 'main'
            buffer = []
            continue
        elif line.lower().startswith('subs:'):
            current_section = 'subs'
            buffer = []
            continue

        # 主账号配置解析
        if current_section == 'main':
            if line.startswith('{'):
                buffer = [line]
            elif buffer:
                buffer.append(line)
            
            try:
                if line.endswith('}'):
                    config['main'] = json.loads('\n'.join(buffer))
                    config['main']['cookies'] = {k: str(v) for k, v in config['main']['cookies'].items()}
            except json.JSONDecodeError as e:
                logging.error(f"主账号配置解析错误（行 {i+1}）: {str(e)}")

        # 小号配置解析
        elif current_section == 'subs' and line.startswith('-'):
            sub_line = line[1:].strip()
            try:
                sub_config = json.loads(sub_line)
                sub_config['cookies'] = {k: str(v) for k, v in sub_config['cookies'].items()}
                config['subs'].append(sub_config)
            except json.JSONDecodeError as e:
                logging.error(f"小号配置解析错误（行 {i+1}）: {str(e)}")
    
    return config

def generate_115_config(config: dict) -> str:
    """生成115配置文件内容（增强版）"""
    content = []
    if config.get('main'):
        # 格式化主账号配置
        main_config = {
            "name": config['main'].get("name", "主账号"),
            "cookies": {
                k: str(v) for k, v in config['main'].get("cookies", {}).items()
            }
        }
        content.append("Main:")
        content.append(json.dumps(main_config, ensure_ascii=False, indent=2))
    
    if config.get('subs'):
        # 格式化小号配置
        content.append("\nSubs:")
        for sub in config['subs']:
            sub_config = {
                "name": sub.get("name", "小号"),
                "cookies": {
                    k: str(v) for k, v in sub.get("cookies", {}).items()
                }
            }
            content.append(f"- {json.dumps(sub_config, ensure_ascii=False, indent=2)}")
    
    return '\n'.join(content)

def validate_115_config(config: dict):
    """验证115配置有效性"""
    required_cookie_fields = ["UID", "CID", "SEID", "KID"]
    
    # 验证主账号
    if not config.get('main'):
        raise ValueError("必须配置主账号")
        
    main_cookies = config['main'].get("cookies", {})
    for field in required_cookie_fields:
        if field not in main_cookies:
            raise ValueError(f"主账号缺少必要Cookie字段: {field}")
        if not isinstance(main_cookies[field], str):
            raise ValueError(f"主账号{field}必须是字符串类型")
    
    # 验证小号
    for i, sub in enumerate(config.get('subs', [])):
        sub_cookies = sub.get("cookies", {})
        for field in required_cookie_fields:
            if field not in sub_cookies:
                raise ValueError(f"小号{i+1}缺少必要Cookie字段: {field}")
            if not isinstance(sub_cookies[field], str):
                raise ValueError(f"小号{i+1}{field}必须是字符串类型")

@app.route('/115_config', methods=['GET', 'POST'])
def handle_115_config():
    """115 配置管理接口（增强版）"""
    if request.method == 'POST':
        try:
            # 解析前端数据
            data = request.json
            main_config = json.loads(data.get('main_config', '{}'))
            subs_config = [json.loads(line) for line in data.get('subs_config', [])]
            schedule_time = data.get('schedule', '08:00')

            # 构建完整配置对象
            full_config = {
                "main": main_config,
                "subs": subs_config
            }

            # 执行配置验证
            validate_115_config(full_config)

            # 生成配置文件内容
            config_content = generate_115_config(full_config)

            # 保存配置文件
            with open(CONFIG115_PATH, 'w', encoding='utf-8') as f:
                f.write(config_content)

            # 更新定时任务
            scheduler.remove_job('115_daily_task')
            hour, minute = map(int, schedule_time.split(':'))
            scheduler.add_job(
                trigger_115_task,
                'cron',
                hour=hour,
                minute=minute,
                id='115_daily_task'
            )

            return jsonify(success=True)
        except json.JSONDecodeError as e:
            return jsonify(success=False, error=f"JSON解析错误: {str(e)}")
        except ValueError as e:
            return jsonify(success=False, error=str(e))
        except Exception as e:
            logging.error(f"配置保存失败: {str(e)}")
            return jsonify(success=False, error="服务器内部错误")
    else:
        try:
            # 读取并返回当前配置
            if not os.path.exists(CONFIG115_PATH):
                # 如果配置文件不存在，返回默认配置
                return jsonify({
                    "main_config": "",
                    "subs_config": [],
                    "schedule": "08:00"
                })
            
            with open(CONFIG115_PATH, 'r', encoding='utf-8') as f:
                content = f.read()
            
            config = parse_115_config(content)
            next_run = scheduler.get_job('115_daily_task').next_run_time.strftime("%H:%M") \
                if scheduler.get_job('115_daily_task') else "08:00"
            
            return jsonify({
                "main_config": json.dumps(config['main'], indent=2, ensure_ascii=False) if config['main'] else '',
                "subs_config": [json.dumps(sub, indent=2, ensure_ascii=False) for sub in config['subs']],
                "schedule": next_run
            })
        except Exception as e:
            logging.error(f"配置加载失败: {str(e)}")
            return jsonify({"error": "配置加载失败"})

def trigger_115_task():
    """触发115定时任务（增强版）"""
    with app.app_context():
        try:
            # 读取最新配置
            with open(CONFIG115_PATH, 'r', encoding='utf-8') as f:
                config_content = f.read()
            
            # 启动任务进程
            process = subprocess.Popen(
                ['python', '115_auto.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                env={
                    **os.environ,
                    "CONFIG_CONTENT": config_content
                }
            )
            logging.info("115定时任务已启动")
        except Exception as e:
            logging.error(f"任务启动失败: {str(e)}")

@app.route('/run_115_task')
def run_115_task():
    """执行115任务并实时推送日志"""
    def generate():
        try:
            # 读取最新配置
            with open(CONFIG115_PATH, 'r', encoding='utf-8') as f:
                config_content = f.read()
            
            # 启动任务进程
            process = subprocess.Popen(
                ['python', '115_auto.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                env={
                    **os.environ,
                    "CONFIG_CONTENT": config_content
                }
            )

            # 实时推送日志
            for line in iter(process.stdout.readline, ''):
                yield f"data: [115] {line}\n\n"
            
            process.stdout.close()
            return_code = process.wait()
            yield f"data: [115] 任务结束，退出码: {return_code}\n\n"
            yield "event: close\ndata: \n\n"
        except Exception as e:
            yield f"data: [ERROR] 任务启动失败: {str(e)}\n\n"
            yield "event: close\ndata: \n\n"

    return Response(stream_with_context(generate()), content_type='text/event-stream')

@app.route('/get_logs')
def get_logs():
    """获取合并日志（增强版）"""
    try:
        logs = []
        
        # 读取115日志
        if os.path.exists(LOG115_PATH):
            with open(LOG115_PATH, 'r', encoding='utf-8') as f:
                for line in f:
                    if '[115]' in line:
                        try:
                            time_part = line[1:20]
                            message = line[22:].strip()
                            logs.append({
                                "time": time_part,
                                "message": f"[115] {message}",
                                "type": "115"
                            })
                        except Exception as e:
                            logging.error(f"日志解析失败: {line} | 错误: {str(e)}")
                            continue
        
        # 读取Web日志
        if os.path.exists("web_strm.log"):
            with open("web_strm.log", 'r', encoding='utf-8') as f:
                for line in f:
                    if ' - ' in line:
                        try:
                            time_str, message = line.split(' - ', 1)
                            logs.append({
                                "time": datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S").strftime("%H:%M:%S"),
                                "message": message.strip(),
                                "type": "web"
                            })
                        except Exception as e:
                            logging.error(f"日志解析失败: {line} | 错误: {str(e)}")
                            continue
        
        # 按时间排序并返回最近200条
        logs.sort(key=lambda x: x['time'], reverse=True)
        return jsonify(logs[:200])
    except Exception as e:
        logging.error(f"日志获取失败: {str(e)}")
        return jsonify([])

# 启动日志优化
logger = logging.getLogger('strm_generator')
logger.info("=== WEBUI已启动 ===")
logger.info("WEBUI地址: http://0.0.0.0:8124")

if __name__ == '__main__':
    # 初始化定时任务
    try:
        if os.path.exists(CONFIG115_PATH):
            with open(CONFIG115_PATH, 'r') as f:
                config = parse_115_config(f.read())
            # 设置默认定时为8:00
            scheduler.add_job(
                trigger_115_task,
                'cron',
                hour=8,
                minute=0,
                id='115_daily_task'
            )
    except Exception as e:
        logging.error(f"定时任务初始化失败: {str(e)}")

    # 启动应用
    from werkzeug.serving import run_simple
    run_simple(
        hostname='0.0.0.0',
        port=8124,
        application=app,
        request_handler=WSGIRequestHandler,
        use_debugger=False,
        use_reloader=False
    )
