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
    echo "            'f871cab818025f1f4781483ea21ccf5d',  # BY123_666ZTJ" >> security.py && \
    echo "            '6d30a34ca9ec1bd5308618a24e40d5bf',  # BY123_269VBR" >> security.py && \
    echo "            'ef3b6917603fb32bbb0bffbb9f9336e7',  # BY123_135HDC" >> security.py && \
    echo "            '13546b91d0543ea599969ce501e6278d'   # BY123_690CDF" >> security.py && \   
    echo "            '0f47294cfbc15e6b800b3044ffedf742',  # BY123_5G8H2K9M" >> security.py && \
    echo "            '8d27b87d1e7f3f99fd6f00cbe65fe610',  # BY123_7J3F9K2L" >> security.py && \
    echo "            'dd3dea2a4f89d3b7db9df6b5a38dc44f',  # BY123_R4T6Y8U1" >> security.py && \
    echo "            '9f4b1a191ca427d5109b5690d47b1b69',  # BY123_Q9W2E4R6" >> security.py && \
    echo "            'fc5378de7343df1580a84eb59ef739f3',  # BY123_Z3X5C7V9" >> security.py && \
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
