#!/bin/bash

# 远程验证服务地址
AUTH_API_URL="http://158.178.236.135:5000/verify"
MAX_RETRIES=3
DEVICE_ID_FILE="/app/config/device_id"  # 修改为子目录路径

# 生成或读取设备ID（增强兼容性和错误处理）
generate_device_id() {
    # 检查现有设备ID文件
    if [[ -f "$DEVICE_ID_FILE" ]]; then
        echo -e "\033[34m 读取现有设备ID文件\033[0m" >&2
        cat "$DEVICE_ID_FILE"
        return
    fi

    # 尝试通过多种方式生成设备ID
    echo -e "\033[34m 生成新的设备ID\033[0m" >&2
    if command -v uuidgen &> /dev/null; then
        device_id=$(uuidgen)
    elif [[ -e /proc/sys/kernel/random/uuid ]]; then
        device_id=$(cat /proc/sys/kernel/random/uuid)
    elif command -v openssl &> /dev/null; then
        device_id=$(openssl rand -hex 16)
    else
        echo -e "\033[31m[错误] 无法生成设备ID：缺少 uuidgen、openssl 或 /proc 支持\033[0m" >&2
        exit 1
    fi

    # 保存设备ID到文件（确保目录可写）
    mkdir -p "$(dirname "$DEVICE_ID_FILE")"  # 创建父目录
    if ! echo "$device_id" > "$DEVICE_ID_FILE"; then
        echo -e "\033[31m[错误] 无法写入设备ID文件：权限不足\033[0m" >&2
        exit 1
    fi
    chmod 600 "$DEVICE_ID_FILE"
    echo "$device_id"
}

# 生成设备ID（带错误捕获）
if ! DEVICE_ID=$(generate_device_id); then
    exit 1
fi

# 检查环境变量 AUTH_KEY
if [[ -z "${AUTH_KEY}" ]]; then
    echo -e "\033[31m[错误] 未提供授权码，请通过 -e AUTH_KEY=xxx 设置环境变量\033[0m" >&2
    exit 1
fi

# 发送验证请求（带详细调试信息）
verify_auth_key() {
    local retries=0
    while [[ $retries -lt $MAX_RETRIES ]]; do
        echo -e "\033[34m 正在验证：auth_key=${AUTH_KEY}, device_id=${DEVICE_ID}\033[0m" >&2

        # 发送请求并捕获 HTTP 状态码和响应体
        response=$(curl -sSf -X POST \
            -w "\n%{http_code}" \
            -H "Content-Type: application/json" \
            -d "{\"auth_key\": \"${AUTH_KEY}\", \"device_id\": \"${DEVICE_ID}\"}" \
            --connect-timeout 10 \
            --max-time 20 \
            "${AUTH_API_URL}" 2>&1)

        # 分离 HTTP 状态码和响应体
        http_code=$(echo "$response" | tail -n 1)
        response_body=$(echo "$response" | head -n -1)

        # 调试输出
        #echo -e "\033[34m[调试] HTTP状态码：${http_code}\033[0m" >&2
        #echo -e "\033[34m[调试] 服务端响应：${response_body}\033[0m" >&2

        # 处理响应
        case "$http_code" in
            200)
                if [[ "$response_body" == *"\"valid\":true"* ]]; then
                    echo -e "\033[32m[成功] 授权验证通过\033[0m" >&2
                    return 0
                else
                    echo -e "\033[31m[错误] 服务端返回矛盾状态\033[0m" >&2
                    return 1
                fi
                ;;
            401)
                echo -e "\033[31m[错误] 授权码无效或已过期\033[0m" >&2
                return 1
                ;;
            403)
                echo -e "\033[31m[错误] 授权码已被其他设备使用\033[0m" >&2
                return 1
                ;;
            *)
                echo -e "\033[33m[警告] 验证服务不可用（尝试 $((retries+1))/$MAX_RETRIES）\033[0m" >&2
                retries=$((retries+1))
                sleep 5
                ;;
        esac
    done
    echo -e "\033[31m[错误] 无法连接验证服务，请检查网络或联系管理员\033[0m" >&2
    return 1
}

# 执行验证
if ! verify_auth_key; then
    exit 1
fi

# 验证通过后执行后续命令
exec "$@"
