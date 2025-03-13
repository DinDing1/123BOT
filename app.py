from flask import Flask, render_template, request, jsonify, Response, stream_with_context, session
import subprocess
import os
import logging
import sys
import io
from dotenv import load_dotenv
from auth import get_user_info_with_password  # 导入 get_user_info_with_password 函数

# 加载环境变量
load_dotenv()

# 初始化 Flask 应用
app = Flask(__name__)
app.secret_key = os.urandom(24)

# 强制标准输出和错误输出使用 UTF-8 编码
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("web_strm.log", encoding='utf-8'),  # 日志文件使用 UTF-8 编码
        logging.StreamHandler(sys.stdout)  # 终端输出使用 UTF-8 编码
    ]
)

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
        user_info = get_user_info_with_password(passport, password)  # 调用导入的函数
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
        # 获取 URL 参数
        config_params = {
            'p123_user': request.args.get('p123_user'),
            'p123_pass': request.args.get('p123_pass'),
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

        # 验证必填字段
        if not all([config_params['p123_user'], config_params['p123_pass']]):
            def generate_error():
                yield "event: error\ndata: 用户名和密码不能为空\n\n"
                yield "event: close\ndata: \n\n"
            return Response(stream_with_context(generate_error()), content_type='text/event-stream')

        # 构造环境变量
        env = os.environ.copy()
        env.update({
            'P123_USER': config_params['p123_user'],
            'P123_PASS': config_params['p123_pass'],
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

# 启动日志
logger = logging.getLogger('strm_generator')
logger.info("\n\n=== WEBUI已启动 ===")
logger.info(f"监听地址: http://0.0.0.0:8124\n")

if __name__ == '__main__':
    # 启动 Flask 应用
    app.run(host='0.0.0.0', port=8124, debug=True)
