# 第一阶段：构建依赖和编译
FROM python:3.12-slim AS builder

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

# 安装依赖（修复 p115client 安装问题）
COPY requirements.txt .
RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir pyinstaller==6.2.0

# 复制源码
COPY . .

# 添加安全检测代码到脚本开头（已移除容器逃逸检测）
RUN echo "import sys, os" > security.py && \
    echo "def security_check():" >> security.py && \
    echo "    # 检测调试器" >> security.py && \
    echo "    if sys.gettrace() is not None:" >> security.py && \
    echo "        sys.exit('Debugger detected! Exiting for security.')" >> security.py && \
    echo "    # 检测调试环境变量" >> security.py && \
    echo "    if os.environ.get('PYTHON_DEBUG'):" >> security.py && \
    echo "        sys.exit('Debug environment detected! Exiting for security.')" >> security.py && \
    echo "security_check()" >> security.py

# 将安全检测代码和主脚本合并
RUN cat security.py 123pan_bot.py > protected_bot.py

# 使用PyInstaller编译
RUN pyinstaller --onefile --name pan_bot \
    --hidden-import=sqlite3 \
    --hidden-import=telegram.ext \
    --hidden-import=requests \
    --hidden-import=urllib3 \
    --clean \
    --strip \
    --noconfirm \
    protected_bot.py

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
    && rm -rf /var/lib/apt/lists/*

# 设置数据卷
VOLUME /data

# 设置入口点
ENTRYPOINT ["/app/pan_bot"]
