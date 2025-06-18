FROM python:3.11-slim

WORKDIR /app

# 安装依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制源码并预编译.pyc文件
COPY . .
RUN python -m compileall .

# 设置环境
ENV DB_PATH="/data/bot123.db"
VOLUME /data

# 运行预编译的字节码
CMD ["python", "__pycache__/123pan_bot.cpython-311.pyc"]
