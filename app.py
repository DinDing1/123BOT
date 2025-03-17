from flask import Flask, render_template, request, jsonify, Response, stream_with_context, session
import subprocess
import os
import logging
import sys
import io
import sqlite3
import json
from dotenv import load_dotenv
from auth import get_user_info_with_password
from werkzeug.serving import WSGIRequestHandler

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler("web_strm.log", encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

class SilentWSGIRequestHandler(WSGIRequestHandler):
    def log(self, type: str, message: str, *args) -> None:
        pass

logging.getLogger('werkzeug').disabled = True
logging.getLogger('flask.app').setLevel(logging.ERROR)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("p123").setLevel(logging.WARNING)

CACHE_DB = "/app/cache/download_cache.db"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        passport = data.get('passport')
        password = data.get('password')
        
        user_info = get_user_info_with_password(passport, password)
        if user_info.get("code") != 0:
            return jsonify({"success": False, "message": user_info.get("message", "登录失败")})

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

@app.route('/115_config', methods=['GET', 'POST'])
def handle_115_config():
    if not session.get('logged_in'):
        return jsonify({"success": False})
    
    user_id = session['user_info']['uid']
    
    if request.method == 'POST':
        data = request.json
        try:
            with sqlite3.connect(CACHE_DB) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO auto115_config 
                    (user_id, main_cookies, sub_accounts, wish_content, schedule_time)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    user_id,
                    json.dumps(data.get('main')),
                    json.dumps(data.get('subs')),
                    data.get('content', '求一本钢铁是怎样炼成得书'),
                    data.get('schedule', '08:00')
                ))
            return jsonify({"success": True})
        except Exception as e:
            logging.error(f"配置保存失败: {str(e)}")
            return jsonify({"success": False, "message": "配置保存失败"})
    
    else:
        try:
            with sqlite3.connect(CACHE_DB) as conn:
                row = conn.execute('''
                    SELECT main_cookies, sub_accounts, wish_content, schedule_time 
                    FROM auto115_config WHERE user_id = ?
                ''', (user_id,)).fetchone()
            
            if row:
                return jsonify({
                    "main": json.loads(row[0]),
                    "subs": json.loads(row[1]),
                    "content": row[2],
                    "schedule_time": row[3]
                })
            return jsonify({})
        except Exception as e:
            logging.error(f"配置读取失败: {str(e)}")
            return jsonify({})

@app.route('/115_run_now', methods=['POST'])
def run_115_now():
    if not session.get('logged_in'):
        return jsonify({"success": False})
    
    try:
        user_id = session['user_info']['uid']
        subprocess.Popen([
            'python', '/app/main.py',
            '--execute-115', user_id
        ])
        return jsonify({"success": True})
    except Exception as e:
        logging.error(f"立即执行失败: {str(e)}")
        return jsonify({"success": False})

@app.route('/generate', methods=['GET'])
def generate_strm():
    if not session.get('logged_in'):
        def generate_error():
            yield "event: error\ndata: 请先登录\n\n"
            yield "event: close\ndata: \n\n"
        return Response(stream_with_context(generate_error()), content_type='text/event-stream')

    try:
        user_info = session.get('user_info', {})
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

        env = os.environ.copy()
        env.update({
            'P123_USER': user_info.get('passport', ''),
            'P123_PASS': request.args.get('p123_pass', ''),
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

        def generate():
            try:
                process = subprocess.Popen(
                    ['python', 'generate_strm.py'],
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding='utf-8'
                )

                for line in iter(process.stdout.readline, ''):
                    yield f"data: {line}\n\n"
                process.stdout.close()
                return_code = process.wait()
                yield f"data: PROCESS_EXIT_CODE:{return_code}\n\n"
                yield "event: close\ndata: \n\n"
            except Exception as e:
                yield f"event: error\ndata: 子进程启动失败: {str(e)}\n\n"
                yield "event: close\ndata: \n\n"

        return Response(stream_with_context(generate()), content_type='text/event-stream')

    except Exception as e:
        def generate_error():
            yield f"event: error\ndata: 生成失败: {str(e)}\n\n"
            yield "event: close\ndata: \n\n"
        return Response(stream_with_context(generate_error()), content_type='text/event-stream')

logger = logging.getLogger('strm_generator')
logger.info("=== WEBUI已启动 ===")
logger.info("WEBUI地址: http://0.0.0.0:8124")

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    run_simple(
        hostname='0.0.0.0',
        port=8124,
        application=app,
        request_handler=SilentWSGIRequestHandler,
        use_debugger=False,
        use_reloader=False
    )
