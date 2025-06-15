# 第一阶段：构建依赖
FROM python:3.11-slim as builder

WORKDIR /app

# 安装构建依赖并复制文件
RUN apt-get update && apt-get install -y --no-install-recommends gcc
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# 第二阶段：最终镜像
FROM python:3.11-slim

WORKDIR /app

# 从构建阶段复制依赖
COPY --from=builder /root/.local /root/.local
COPY . .

# 设置环境变量和路径
ENV PATH="/root/.local/bin:${PATH}"
ENV DB_PATH="/data/bot123.db"
VOLUME /data

# 设置默认环境变量（可在运行时覆盖）
ENV TG_BOT_TOKEN=""
ENV PAN_CLIENT_ID=""
ENV PAN_CLIENT_SECRET=""
ENV TG_ADMIN_USER_IDS=""
ENV DEFAULT_SAVE_DIR=""
ENV EXPORT_BASE_DIR=""
ENV SEARCH_MAX_DEPTH=

# 设置入口点
CMD ["python", "123pan_bot.py"]
