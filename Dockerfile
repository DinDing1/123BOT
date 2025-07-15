# 第一阶段：构建依赖和安全验证
FROM python:3.12-slim AS builder

# 强制要求构建时间戳参数（必须通过--build-arg传入）
ARG BUILD_TIMESTAMP
RUN test -n "$BUILD_TIMESTAMP" || (echo "❌ 错误：必须提供BUILD_TIMESTAMP构建参数" && exit 1)

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
    && rm -rf /var/lib/apt/lists/*

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir pyinstaller==6.2.0

# 复制源码并重命名主文件
COPY . .
RUN mv 123pan_bot.py pan_bot_main.py && \
    echo "from pan_bot_main import main" > __main__.py

# 创建带严格时间验证的入口脚本
RUN echo "import sys, os, time" > entrypoint.py && \
    echo "def security_check():" >> entrypoint.py && \
    echo "    try:" >> entrypoint.py && \
    echo "        build_timestamp = int(os.getenv('BUILD_TIMESTAMP', '$BUILD_TIMESTAMP'))" >> entrypoint.py && \
    echo "        current_time = time.time()" >> entrypoint.py && \
    echo "        expiry_days = 30" >> entrypoint.py && \
    echo "        expiry_seconds = expiry_days * 24 * 3600" >> entrypoint.py && \
    echo "        print(f'[安全验证] 构建时间: {time.ctime(build_timestamp)}')" >> entrypoint.py && \
    echo "        print(f'[安全验证] 当前时间: {time.ctime(current_time)}')" >> entrypoint.py && \
    echo "        print(f'[安全验证] 有效期: {expiry_days}天')" >> entrypoint.py && \
    echo "        if current_time < build_timestamp:" >> entrypoint.py && \
    echo "            sys.exit('❌ 安全验证失败：系统时间异常！检测到时间回溯')" >> entrypoint.py && \
    echo "        if current_time - build_timestamp > expiry_seconds:" >> entrypoint.py && \
    echo "            remaining_days = -((current_time - build_timestamp - expiry_seconds) // (24*3600))" >> entrypoint.py && \
    echo "            sys.exit(f'❌ 安全验证失败：镜像已过期！请重新构建。已过期: {remaining_days}天')" >> entrypoint.py && \
    echo "        print('✅ 安全验证通过，启动机器人...')" >> entrypoint.py && \
    echo "    except Exception as e:" >> entrypoint.py && \
    echo "        sys.exit(f'❌ 安全验证异常: {str(e)}')" >> entrypoint.py && \
    echo "security_check()" >> entrypoint.py && \
    echo "from pan_bot_main import main" >> entrypoint.py && \
    echo "if __name__ == '__main__':" >> entrypoint.py && \
    echo "    main()" >> entrypoint.py

# 使用PyInstaller编译
RUN pyinstaller --onefile --name pan_bot \
    --hidden-import=pan_bot_main \
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

# 强制继承构建时间戳
ARG BUILD_TIMESTAMP
ENV BUILD_TIMESTAMP=$BUILD_TIMESTAMP

# 设置时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app

# 创建数据目录并设置权限
RUN mkdir -p /data && chmod 777 /data

# 从构建阶段复制编译后的程序
COPY --from=builder /app/dist/pan_bot /app/
COPY --from=builder /app/pan_bot_main.py /app/
COPY --from=builder /app/VERSION /app/

# 安装运行时最小依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

# 设置数据卷
VOLUME /data

# 设置入口点
ENTRYPOINT ["/app/pan_bot"]
