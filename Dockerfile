# 第一阶段：构建依赖和安全验证
FROM python:3.12-slim AS builder

# 强制要求构建时间戳参数
ARG BUILD_TIMESTAMP
RUN test -n "$BUILD_TIMESTAMP" || (echo "❌ 错误：必须提供BUILD_TIMESTAMP构建参数" && exit 1)

# 设置时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app

# 安装构建依赖（移除了UPX）
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

# 复制源码
COPY . .

# 创建安全验证包装脚本
RUN echo "import sys, os, time" > wrapper.py && \
    echo "def security_check():" >> wrapper.py && \
    echo "    try:" >> wrapper.py && \
    echo "        build_timestamp = int(os.getenv('BUILD_TIMESTAMP', '$BUILD_TIMESTAMP'))" >> wrapper.py && \
    echo "        current_time = time.time()" >> wrapper.py && \
    echo "        expiry_days = 30" >> wrapper.py && \
    echo "        expiry_seconds = expiry_days * 24 * 3600" >> wrapper.py && \
    echo "        print(f'[安全验证] 构建时间: {time.ctime(build_timestamp)}')" >> wrapper.py && \
    echo "        print(f'[安全验证] 当前时间: {time.ctime(current_time)}')" >> wrapper.py && \
    echo "        print(f'[安全验证] 有效期: {expiry_days}天')" >> wrapper.py && \
    echo "        if current_time < build_timestamp:" >> wrapper.py && \
    echo "            sys.exit('❌ 安全验证失败：系统时间异常！检测到时间回溯')" >> wrapper.py && \
    echo "        if current_time - build_timestamp > expiry_seconds:" >> wrapper.py && \
    echo "            remaining_days = -((current_time - build_timestamp - expiry_seconds) // (24*3600))" >> wrapper.py && \
    echo "            sys.exit(f'❌ 安全验证失败：镜像已过期！请重新构建。已过期: {remaining_days}天')" >> wrapper.py && \
    echo "        print('✅ 安全验证通过')" >> wrapper.py && \
    echo "        return True" >> wrapper.py && \
    echo "    except Exception as e:" >> wrapper.py && \
    echo "        sys.exit(f'❌ 安全验证异常: {str(e)}')" >> wrapper.py && \
    echo "if __name__ == '__main__':" >> wrapper.py && \
    echo "    if security_check():" >> wrapper.py && \
    echo "        from pan_bot_main import main" >> wrapper.py && \
    echo "        main()" >> wrapper.py

# 重命名主脚本以保持导入关系
RUN mv 123pan_bot.py pan_bot_main.py

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
    wrapper.py

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
COPY --from=builder /app/VERSION /app/

# 安装运行时最小依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

# 清理源码痕迹
RUN find /app -name "*.py" -delete && \
    find /app -name "__pycache__" -exec rm -rf {} + && \
    rm -rf /root/.cache /tmp/*

# 设置数据卷
VOLUME /data

# 设置入口点
ENTRYPOINT ["/app/pan_bot"]
