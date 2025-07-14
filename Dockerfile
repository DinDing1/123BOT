# 第一阶段：构建依赖和安全验证
FROM python:3.12-slim AS builder

# 设置构建时的时间戳（作为镜像有效期起始点）
ARG BUILD_TIMESTAMP

# 设置时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

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
    libreadline-dev \
    libffi-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir pyinstaller==6.2.0

# 复制源码
COPY . .

# 创建安全验证入口脚本
RUN echo "import sys, os, time" > entrypoint.py && \
    echo "def security_check():" >> entrypoint.py && \
    # 镜像有效期检查 (30天) >> entrypoint.py && \
    echo "    build_timestamp = $BUILD_TIMESTAMP" >> entrypoint.py && \
    echo "    current_time = time.time()" >> entrypoint.py && \
    echo "    expiry_seconds = 30 * 24 * 3600" >> entrypoint.py && \
    echo "    if current_time < build_timestamp:" >> entrypoint.py && \
    echo "        sys.exit('❌ 系统时间异常！检测到时间回溯')" >> entrypoint.py && \
    echo "    if current_time - build_timestamp > expiry_seconds:" >> entrypoint.py && \
    echo "        sys.exit('❌ 镜像已过期！请重新构建镜像获取更新。有效期: 30天')" >> entrypoint.py && \
    echo "    print('✅ 安全验证通过，启动机器人...')" >> entrypoint.py && \
    echo "security_check()" >> entrypoint.py && \
    echo "from 123pan_bot import main" >> entrypoint.py && \
    echo "if __name__ == '__main__':" >> entrypoint.py && \
    echo "    main()" >> entrypoint.py

# 使用PyInstaller编译（添加必要的隐藏导入）
RUN pyinstaller --onefile --name pan_bot \
    --hidden-import=sqlite3 \
    --hidden-import=telegram.ext \
    --hidden-import=telegram \
    --hidden-import=telegram._updater \
    --hidden-import=telegram.ext._application \
    --hidden-import=requests \
    --hidden-import=urllib3 \
    --hidden-import=hashlib \
    --hidden-import=time \
    --hidden-import=os \
    --hidden-import=sys \
    --hidden-import=warnings \
    --hidden-import=re \
    --hidden-import=json \
    --hidden-import=logging \
    --hidden-import=threading \
    --hidden-import=traceback \
    --hidden-import=contextlib \
    --hidden-import=datetime \
    --hidden-import=functools \
    --hidden-import=concurrent.futures \
    --hidden-import=p115client \
    --clean \
    --strip \
    --noconfirm \
    entrypoint.py

# 第二阶段：最小化运行时环境
FROM python:3.12-slim

# 设置时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app

# 创建数据目录并设置权限
RUN mkdir -p /data && chmod 777 /data

# 从构建阶段复制编译后的程序
COPY --from=builder /app/dist/pan_bot /app/

# 安装运行时最小依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

# 设置数据卷
VOLUME /data

# 设置入口点
ENTRYPOINT ["/app/pan_bot"]
