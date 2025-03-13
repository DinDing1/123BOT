from p123 import P123Client
from typing import Dict

def get_user_info_with_password(passport: str, password: str) -> Dict:
    """获取用户信息（带密码验证）"""
    try:
        client = P123Client(passport, password)
        response = client.open_user_info()
        return response
    except Exception as e:
        return {"code": -1, "message": str(e)}

def format_size(size_bytes: int) -> str:
    """格式化存储空间显示"""
    units = ["字节", "KB", "MB", "GB", "TB"]
    unit_index = 0
    while size_bytes >= 1024 and unit_index < 4:
        size_bytes /= 1024
        unit_index += 1
    return f"{size_bytes:.2f} {units[unit_index]}"
