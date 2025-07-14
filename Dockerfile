# 构建阶段
FROM python:3.12-slim as builder

WORKDIR /app

# 复制源码
COPY 123pan_bot.py .
COPY requirements.txt .

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 编译为pyc并base64编码
RUN python -c "import py_compile, base64; \
    py_compile.compile('123pan_bot.py'); \
    encoded = base64.b64encode(open('__pycache__/123pan_bot.cpython-312.pyc', 'rb').read()); \
    open('encoded_bot.txt', 'wb').write(encoded)"

# 创建 Python 入口点脚本
RUN echo $'import os\n\
import sys\n\
import time\n\
from datetime import datetime\n\
import base64\n\
\n\
def main():\n\
    # 有效期检查（30天）\n\
    BUILD_TIMESTAMP = float(os.getenv("BUILD_TIMESTAMP", "0"))\n\
    EXPIRY_DAYS = 30\n\
    \n\
    if BUILD_TIMESTAMP:\n\
        build_date = datetime.utcfromtimestamp(BUILD_TIMESTAMP)\n\
        current_date = datetime.utcnow()\n\
        days_passed = (current_date - build_date).days\n\
        \n\
        if days_passed > EXPIRY_DAYS:\n\
            print(f"错误：此Docker镜像已过期（构建于 {build_date}）")\n\
            print("请重新构建并拉取最新版本镜像")\n\
            sys.exit(1)\n\
    \n\
    # 调试信息\n\
    print("===== 环境诊断 =====")\n\
    print(f"Python版本: {sys.version}")\n\
    print(f"当前时间: {datetime.utcnow()}")\n\
    if BUILD_TIMESTAMP:\n\
        print(f"构建时间: {build_date}")\n\
        print(f"已运行天数: {days_passed}")\n\
    print("====================")\n\
    \n\
    # 解码并执行\n\
    print("正在解码并启动程序...")\n\
    with open("/app/encoded_bot.txt", "rb") as f:\n\
        encoded = f.read()\n\
    \n\
    with open("/app/bot.pyc", "wb") as f:\n\
        f.write(base64.b64decode(encoded))\n\
    \n\
    # 导入并执行主程序\n\
    from bot import main as bot_main\n\
    bot_main()\n\
\n\
if __name__ == "__main__":\n\
    main()\n' > /app/entrypoint.py

# 运行时阶段
FROM python:3.12-slim

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 复制编码后的程序和入口点
COPY --from=builder /app/encoded_bot.txt .
COPY --from=builder /app/entrypoint.py .
COPY --from=builder /app/requirements.txt .

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 设置构建时间戳
ARG BUILD_TIMESTAMP
ENV BUILD_TIMESTAMP=$BUILD_TIMESTAMP

# 设置环境变量默认值
ENV DB_PATH=/data/bot123.db
VOLUME /data

# 编译入口点
RUN python -c "import py_compile; py_compile.compile('entrypoint.py')"

ENTRYPOINT ["python", "/app/__pycache__/entrypoint.cpython-312.pyc"]