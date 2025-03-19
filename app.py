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

# 115配置文件路径
CONFIG115_PATH = os.getenv('CONFIG115_PATH', '/app/config/115_config.txt')


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

# 初始化调度器
scheduler = BackgroundScheduler()
scheduler.start()

def parse_115_config(content: str) -> dict:
    """解析115配置文件内容"""
    config = {"main": None, "subs": [], "params": {}}
    current_section = None
    for line in content.split('\n'):
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith('main:'):
            current_section = 'main'
            continue
        elif line.lower().startswith('subs:'):
            current_section = 'subs'
            continue
        elif line.startswith('#'):
            continue
        
        if current_section == 'main':
            config['main'] = json.loads(line)
        elif current_section == 'subs' and line.startswith('-'):
            config['subs'].append(json.loads(line[1:].strip()))
    return config

def generate_115_config(config: dict) -> str:
    """生成115配置文件内容"""
    content = []
    if config['main']:
        content.append("Main:")
        content.append(json.dumps(config['main'], ensure_ascii=False))
    if config['subs']:
        content.append("\nSubs:")
        for sub in config['subs']:
            content.append(f"- {json.dumps(sub, ensure_ascii=False)}")
    return '\n'.join(content)

@app.route('/115_config', methods=['GET', 'POST'])
def handle_115_config():
    if request.method == 'POST':
        try:
            # 构造配置文件内容
            config_content = f"Main:\n{request.json['main_config']}\n\nSubs:\n"
            config_content += '\n'.join([f"- {sub}" for sub in request.json['subs_config']])
            
            # 保存配置文件
            with open(CONFIG115_PATH, 'w', encoding='utf-8') as f:
                f.write(config_content)
            
            # 保存运行参数
            with open(CONFIG115_PATH+'.params', 'w') as f:
                json.dump({
                    "max_wishes": request.json['max_wishes'],
                    "delay": request.json['delay'],
                    "schedule": request.json['schedule']
                }, f)
            
            # 更新定时任务
            if request.json['schedule']:
                scheduler.add_job(
                    run_115_task,
                    'cron',
                    hour=int(request.json['schedule'].split(':')[0]),
                    minute=int(request.json['schedule'].split(':')[1]),
                    id='115_daily_task'
                )
            
            return jsonify(success=True)
        except Exception as e:
            return jsonify(success=False, message=str(e))
    else:
        try:
            # 读取配置文件
            with open(CONFIG115_PATH, 'r', encoding='utf-8') as f:
                content = f.read()
            config = parse_115_config(content)
            
            # 读取参数
            with open(CONFIG115_PATH+'.params', 'r') as f:
                params = json.load(f)
            
            return jsonify({
                "main_config": json.dumps(config['main'], indent=2),
                "subs_config": [json.dumps(sub, indent=2) for sub in config['subs']],
                **params
            })
        except:
            return jsonify({})

@app.route('/run_115_task')
def run_115_task():
    def generate():
        # 添加环境变量
        env = os.environ.copy()
        env.update({
            'MAX_WISHES': str(request.args.get('max_wishes', 3)),
            'DELAY': str(request.args.get('delay', 60))
        })
        
        process = subprocess.Popen(
            ['python', '115_auto.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            env=env
        )
        
        for line in iter(process.stdout.readline, ''):
            yield f"data: [115] {line}\n\n"
        process.stdout.close()
        yield "event: close\ndata: \n\n"
    
    return Response(stream_with_context(generate()), content_type='text/event-stream')
    


# 新增：获取历史日志
@app.route('/get_logs')
def get_logs():
    try:
        logs = []
        # 读取WEB日志
        with open("web_strm.log", "r", encoding="utf-8") as f:
            for line in f:
                time_str, message = line.strip().split(" - ", 1)
                logs.append({
                    "time": datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S").strftime("%H:%M:%S"),
                    "message": message
                })
        # 读取115日志
        with open("115_auto.log", "r", encoding="utf-8") as f:
            for line in f:
                if "[115]" in line:
                    time_str = line.split("[115] ")[1].split("]")[0]
                    message = line.split("] ")[2].strip()
                    logs.append({
                        "time": time_str,
                        "message": f"[115] {message}"
                    })
        return jsonify(logs[-100:])  # 返回最近100条日志
    except Exception as e:
        return jsonify([])
        
# 启动日志优化
logger = logging.getLogger('strm_generator')
logger.info("=== WEBUI已启动 ===")
logger.info("WEBUI地址: http://0.0.0.0:8124")

if __name__ == '__main__':
    # 使用自定义的 SilentWSGIRequestHandler 并禁用调试模式
    from werkzeug.serving import run_simple
    run_simple(
        hostname='0.0.0.0',
        port=8124,
        application=app,
        request_handler=SilentWSGIRequestHandler,
        use_debugger=False,
        use_reloader=False
    )
