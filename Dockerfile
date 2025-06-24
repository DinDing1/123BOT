# 第一阶段：构建依赖和编译
FROM python:3.12-slim AS builder

# 设置时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 使用国内APT镜像源加速
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list

WORKDIR /app

# 安装构建依赖 (移除upx)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libssl-dev \
    build-essential \
    zlib1g-dev \
    libncurses5-dev \
    libgdbm-dev \
    libnss3-dev \
    libreadline-dev \
    libffi-dev \
    wget && \
    rm -rf /var/lib/apt/lists/*

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
RUN pip install --no-cache-dir pyinstaller==6.2.0 pyarmor==8.3.0 -i https://pypi.tuna.tsinghua.edu.cn/simple

# 复制源码并加密
COPY . .
RUN pyarmor gen --output /app/encrypted --platform linux.x86_64 --exact 123pan_bot.py
RUN pyinstaller --onefile --name pan_bot --add-data "encrypted:encrypted" \
    --hidden-import=sqlite3 --hidden-import=telegram.ext \
    --hidden-import=requests --hidden-import=urllib3 \
    --key=${BUILD_KEY:-MyDefaultSecret123!} encrypted/123pan_bot.py

# 第二阶段：最小化运行时环境
FROM python:3.12-slim

# 设置时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app

# 从构建阶段复制编译后的程序
COPY --from=builder /app/dist/pan_bot /app/
COPY --from=builder /app/VERSION /app/

# 安装运行时最小依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 设置数据卷
VOLUME /data

# 设置入口点
ENTRYPOINT ["/app/pan_bot"]
