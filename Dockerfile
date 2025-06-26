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

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir pyinstaller==6.2.0

# 复制源码
COPY . .

# 添加安全检测代码到脚本开头
RUN echo "import sys, os, hashlib" > security.py && \
    echo "def security_check():" >> security.py && \
    echo "    # 检测调试器" >> security.py && \
    echo "    if sys.gettrace() is not None:" >> security.py && \
    echo "        sys.exit('Debugger detected! Exiting for security.')" >> security.py && \
    echo "    # 检测调试环境变量" >> security.py && \
    echo "    if os.environ.get('PYTHON_DEBUG'):" >> security.py && \
    echo "        sys.exit('Debug environment detected! Exiting for security.')" >> security.py && \
    # 添加授权验证函数
    echo "    def verify_license(license_key):" >> security.py && \
    echo "        valid_hashes = [" >> security.py && \
    # 添加50组安全许可证密钥前三已用
    echo "            '7f5b1a7c7d7b1e3e1f1b3a5d1e3f5a7d',  # BY123_5G8H2K9M" >> security.py && \
    echo "            'a3d5f7c9e1b3a5d7f9c1e3f5a7b9d1f3',  # BY123_7J3F9K2L" >> security.py && \
    echo "            '5b9d1f3a7c9e1b3d5f7a9c1e3f5b7d9f',  # BY123_R4T6Y8U1" >> security.py && \
    echo "            '3f5a7b9d1f3a5b7d9f1c3e5f7a9c1e3f',  # BY123_Q9W2E4R6" >> security.py && \
    echo "            '9c1e3f5b7d9f1a3c5e7f9b1d3f5a7c9e',  # BY123_Z3X5C7V9" >> security.py && \
    echo "            '1d3f5a7c9e1b3d5f7a9c1e3f5b7d9f1',  # BY123_B8N0M2K4" >> security.py && \
    echo "            '7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7',  # BY123_J6H8G0F2" >> security.py && \
    echo "            '3e5f7a9c1e3f5b7d9f1a3c5e7f9b1d3',  # BY123_D4S6A8F9" >> security.py && \
    echo "            '5a7c9e1b3d5f7a9c1e3f5b7d9f1a3c5',  # BY123_P1O3I5U7" >> security.py && \
    echo "            '9f1a3c5e7f9b1d3f5a7c9e1b3d5f7a9',  # BY123_Y7T5R3E1" >> security.py && \
    echo "            '2d4f6a8c0e2b4d6f8a0c2e4f6a8c0e2',  # BY123_L9K8J7H6" >> security.py && \
    echo "            '6f8a0c2e4f6a8c0e2b4d6f8a0c2e4f6',  # BY123_V5B4N3M2" >> security.py && \
    echo "            '0e2b4d6f8a0c2e4f6a8c0e2b4d6f8a0',  # BY123_C1X2Z3Y4" >> security.py && \
    echo "            '4f6a8c0e2b4d6f8a0c2e4f6a8c0e2b4',  # BY123_U9I8O7P6" >> security.py && \
    echo "            '8c0e2b4d6f8a0c2e4f6a8c0e2b4d6f8',  # BY123_S5A6D7F8" >> security.py && \
    echo "            'b4d6f8a0c2e4f6a8c0e2b4d6f8a0c2',  # BY123_G9H0J1K2" >> security.py && \
    echo "            'a0c2e4f6a8c0e2b4d6f8a0c2e4f6a8',  # BY123_M3N4B5V6" >> security.py && \
    echo "            'e2b4d6f8a0c2e4f6a8c0e2b4d6f8a0',  # BY123_R7T8Y9U0" >> security.py && \
    echo "            '6a8c0e2b4d6f8a0c2e4f6a8c0e2b4d6',  # BY123_W1Q2E3R4" >> security.py && \
    echo "            'd6f8a0c2e4f6a8c0e2b4d6f8a0c2e4',  # BY123_T5Y6U7I8" >> security.py && \
    echo "            '3c5e7f9b1d3f5a7c9e1b3d5f7a9c1e3',  # BY123_F9G8H7J6" >> security.py && \
    echo "            '1b3d5f7a9c1e3f5b7d9f1a3c5e7f9b1',  # BY123_K4L3Z2X1" >> security.py && \
    echo "            '7d9f1a3c5e7f9b1d3f5a7c9e1b3d5f7',  # BY123_V0C9X8B7" >> security.py && \
    echo "            'f1a3c5e7f9b1d3f5a7c9e1b3d5f7a9',  # BY123_N6M5Q4W3" >> security.py && \
    echo "            'a9c1e3f5b7d9f1a3c5e7f9b1d3f5a7',  # BY123_E2R1T9Y8" >> security.py && \
    echo "            '5d7f9c1e3f5a7b9d1f3a5b7d9f1c3e5',  # BY123_U7I6O5P4" >> security.py && \
    echo "            'e1b3d5f7a9c1e3f5b7d9f1a3c5e7f9',  # BY123_S3A2D1F0" >> security.py && \
    echo "            'b1d3f5a7c9e1b3d5f7a9c1e3f5b7d9',  # BY123_G8H9J0K1" >> security.py && \
    echo "            '3a5b7d9f1c3e5f7a9c1e3f5b7d9f1a',  # BY123_L2Z3X4C5" >> security.py && \
    echo "            '9b1d3f5a7c9e1b3d5f7a9c1e3f5b7d',  # BY123_V6B7N8M9" >> security.py && \
    echo "            'd1f3a5b7d9f1c3e5f7a9c1e3f5b7d9',  # BY123_Q0W9E8R7" >> security.py && \
    echo "            'f5a7c9e1b3d5f7a9c1e3f5b7d9f1a3',  # BY123_T6Y5U4I3" >> security.py && \
    echo "            'c1e3f5b7d9f1a3c5e7f9b1d3f5a7c9',  # BY123_O2P1I9U8" >> security.py && \
    echo "            '7f9b1d3f5a7c9e1b3d5f7a9c1e3f5b',  # BY123_H7J6K5L4" >> security.py && \
    echo "            '3f5b7d9f1a3c5e7f9b1d3f5a7c9e1',  # BY123_F3G4H5J6" >> security.py && \
    echo "            'b7d9f1a3c5e7f9b1d3f5a7c9e1b3d5',  # BY123_K9L0Z1X2" >> security.py && \
    echo "            '1f3a5b7d9f1c3e5f7a9c1e3f5b7d9f',  # BY123_C8V9B0N1" >> security.py && \
    echo "            '5f7a9c1e3f5b7d9f1a3c5e7f9b1d3f',  # BY123_M4N5B6V7" >> security.py && \
    echo "            '9d1f3a5b7d9f1c3e5f7a9c1e3f5b7d',  # BY123_E1R2T3Y4" >> security.py && \
    echo "            'd9f1a3c5e7f9b1d3f5a7c9e1b3d5f7',  # BY123_U0I9O8P7" >> security.py && \
    echo "            'f7a9c1e3f5b7d9f1a3c5e7f9b1d3f5',  # BY123_S6A7D8F9" >> security.py && \
    echo "            'c9e1b3d5f7a9c1e3f5b7d9f1a3c5e7',  # BY123_G0H1J2K3" >> security.py && \
    echo "            '1e3f5b7d9f1a3c5e7f9b1d3f5a7c9e',  # BY123_L5Z6X7C8" >> security.py && \
    echo "            'b3d5f7a9c1e3f5b7d9f1a3c5e7f9b1',  # BY123_V2B3N4M5" >> security.py && \
    echo "            'd5f7a9c1e3f5b7d9f1a3c5e7f9b1d3',  # BY123_Q1W2E3R4" >> security.py && \
    echo "            'a7c9e1b3d5f7a9c1e3f5b7d9f1a3c5',  # BY123_T7Y8U9I0" >> security.py && \
    echo "            'e3f5b7d9f1a3c5e7f9b1d3f5a7c9e',  # BY123_O3P4I5U6" >> security.py && \
    echo "            'f9b1d3f5a7c9e1b3d5f7a9c1e3f5b7',  # BY123_H8J9K0L1" >> security.py && \
    echo "            '5e7f9b1d3f5a7c9e1b3d5f7a9c1e3f',  # BY123_F4G5H6J7" >> security.py && \
    echo "            '9f1c3e5f7a9c1e3f5b7d9f1a3c5e7f',  # BY123_K1L2Z3X4" >> security.py && \
    echo "            '3e5f7a9c1e3f5b7d9f1a3c5e7f9b1d',  # BY123_C9V0B1N2" >> security.py && \
    echo "            '7a9c1e3f5b7d9f1a3c5e7f9b1d3f5a'   # BY123_M5N6B7V8" >> security.py && \
    echo "        ]" >> security.py && \
    echo "        hash_md5 = hashlib.md5(license_key.encode('utf-8')).hexdigest()" >> security.py && \
    echo "        return hash_md5 in valid_hashes" >> security.py && \
    # 检查环境变量中的许可证
    echo "    license_key = os.getenv('PAN_BOT_LICENSE', '')" >> security.py && \
    echo "    if not license_key:" >> security.py && \
    echo "        sys.exit('❌ 未提供许可证密钥，请设置PAN_BOT_LICENSE环境变量')" >> security.py && \
    echo "    if not verify_license(license_key):" >> security.py && \
    echo "        sys.exit('❌ 许可证密钥无效或已过期')" >> security.py && \
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
