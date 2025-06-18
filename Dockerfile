# 第一阶段：构建依赖和编译
FROM python:3.11-slim as builder

WORKDIR /app

# 安装构建依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libssl-dev \
    build-essential \
    zlib1g-dev \
    libncurses5-dev \
    libgdbm-dev \
    libnss3-dev \
    libssl-dev \
    libreadline-dev \
    libffi-dev \
    wget

# 安装依赖到系统目录而不是用户目录
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir pyinstaller==6.2.0

# 复制源码
COPY . .

# 编译Python脚本为可执行文件
RUN pyinstaller --onefile --name pan_bot 123pan_bot.py

# 第二阶段：最终镜像
FROM python:3.11-slim

WORKDIR /app

# 从构建阶段复制编译后的程序
COPY --from=builder /app/dist/pan_bot /app/

# 安装运行时依赖（直接安装到系统目录）
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 设置环境变量和路径
ENV DB_PATH="/data/bot123.db"
VOLUME /data

# 设置默认环境变量
ENV TG_BOT_TOKEN=""
ENV PAN_CLIENT_ID=""
ENV PAN_CLIENT_SECRET=""
ENV TG_ADMIN_USER_IDS=""
ENV DEFAULT_SAVE_DIR=""
ENV EXPORT_BASE_DIR=""
ENV SEARCH_MAX_DEPTH=""

# 设置入口点
CMD ["/app/pan_bot"]
