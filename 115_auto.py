#!/usr/bin/env python3
# encoding: utf-8

"""
115全功能自动化脚本（修复版）
功能：全账号签到 → 智能许愿 → 批量助愿 → 批量采纳
"""

__version__ = "5.3.1"  # 版本号更新

import json
import sys
import time
from typing import Dict, List
from tenacity import retry, stop_after_attempt, wait_fixed  # 新增重试机制

from p115client import P115Client, check_response

# 配置文件路径
CONFIG_FILE = "115_config.txt"
# 日志文件路径
LOG_FILE = "115_auto.log"
# 最大许愿次数（根据115规则调整）
MAX_WISHES = 3
# 操作间隔时间（秒）
DELAY = 60

######################
#  配置文件解析（修复版）
######################
def load_config() -> Dict:
    """加载TXT格式配置文件（修复版）"""
    config = {"main": None, "subs": []}
    current_section = None
    
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            raw_content = f.read()
        
        # 处理Windows换行符
        lines = [line.strip() for line in raw_content.replace('\r\n', '\n').split('\n')]
        
        buffer = []
        for line in lines:
            if not line or line.startswith("#"):
                continue
            
            if line.lower().startswith("main:"):
                current_section = "main"
                buffer = []
                continue
            elif line.lower().startswith("subs:"):
                current_section = "subs"
                buffer = []
                continue
            
            if current_section == "main":
                buffer.append(line)
                if line.endswith("}"):
                    config["main"] = parse_account("".join(buffer))
                    buffer = []
            elif current_section == "subs" and line.startswith("-"):
                sub_line = line[1:].strip()
                try:
                    sub_config = json.loads(sub_line)
                    # 显式转换cookies字段为字符串
                    if "cookies" in sub_config:
                        sub_config["cookies"] = {k: str(v) for k, v in sub_config["cookies"].items()}
                    config["subs"].append(sub_config)
                except json.JSONDecodeError as e:
                    log(f"小号配置解析错误: {sub_line} | 错误: {str(e)}", "ERROR")
        
        if not config["main"]:
            raise ValueError("未配置主账号")
        if not config["subs"]:
            raise ValueError("未配置小号")
        return config
    except Exception as e:
        log(f"配置文件解析失败: {str(e)}", "ERROR")
        sys.exit(1)

def parse_account(line: str) -> Dict:
    """解析账号配置（修复版）"""
    try:
        account = json.loads(line)
        # 显式转换cookies字段为字符串
        if "cookies" in account:
            account["cookies"] = {k: str(v) for k, v in account["cookies"].items()}
        return account
    except json.JSONDecodeError as e:
        raise ValueError(f"无效的账号配置: {line} | 错误: {str(e)}")

######################
#  签到模块（修复版）
######################
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def safe_checkin(client: P115Client):
    """带重试机制的签到函数"""
    return client.user_points_sign_post()

def checkin_all(config: Dict):
    """执行全账号签到（修复版）"""
    accounts = [config["main"]] + config["subs"]
    total = len(accounts)
    success = 0
    
    log(f"开始签到流程，共 {total} 个账号")
    for account in accounts:
        name = account.get("name", "未命名账号")
        try:
            # 显式转换cookies值为字符串
            cookies = {k: str(v) for k, v in account["cookies"].items()}
            client = P115Client(cookies, check_for_relogin=True)
            
            result = safe_checkin(client)
            if result.get("state"):
                days = result.get("data", {}).get("continuous_day", 0)
                log(f"{name} 签到成功，连续签到{days}天")
                success += 1
            time.sleep(3)
        except Exception as e:
            log(f"{name} 签到失败: {str(e)}", "ERROR")
    
    log(f"签到完成，成功 {success}/{total} 个账号")

######################
#  许愿树模块（修复版）
######################
class SmartWishSystem:
    """智能许愿管理系统（修复版）"""
    
    def __init__(self, main_account: Dict, sub_accounts: List[Dict]):
        # 显式转换cookies值为字符串
        main_cookies = {k: str(v) for k, v in main_account["cookies"].items()}
        self.main_client = P115Client(main_cookies, check_for_relogin=True)
        self.sub_accounts = sub_accounts
        self.main_name = main_account.get("name", "主账号")
        self.wish_map = {}  # 存储许愿信息
    
    def full_process(self):
        """完整智能流程"""
        log("开始智能许愿流程".center(40, "="))
        
        # 阶段1：创建许愿
        self.create_wishes()
        time.sleep(DELAY)  # 许愿后延迟
        
        # 阶段2：批量助愿
        aid_map = self.process_aiding()
        time.sleep(DELAY)  # 助愿后延迟
        
        # 阶段3：批量采纳
        self.process_adoption(aid_map)
        
        log("智能许愿流程完成".center(40, "="))
    
    def create_wishes(self):
        """创建许愿（增加cookie有效性验证）"""
        for sub in self.sub_accounts:
            try:
                # 验证cookies有效性
                test_client = P115Client(sub["cookies"], check_for_relogin=True)
                check_response(test_client.get_user_info())  # 测试接口
            except Exception as e:
                log(f"{sub['name']} cookies失效，跳过处理: {str(e)}", "ERROR")
                continue
            
            client = P115Client(sub["cookies"], check_for_relogin=True)
            name = sub.get("name", "小号")
            self.wish_map[name] = {"client": client, "all_wishes": []}
            
            try:
                # 获取现有许愿
                active_wishes = self.get_active_wishes(client)
                self.wish_map[name]["all_wishes"] = active_wishes
                log(f"{name} 现有许愿: {len(active_wishes)} 个")
                
                # 补足新许愿
                if len(active_wishes) < MAX_WISHES:
                    for _ in range(MAX_WISHES - len(active_wishes)):
                        wish_id = check_response(client.act_xys_wish(
                            {"rewardSpace": 5, "content": "求一本钢铁是怎样炼成的书"}
                        ))["data"]["xys_id"]
                        self.wish_map[name]["all_wishes"].append(wish_id)
                        log(f"{name} 创建新许愿 ID: {wish_id}")
                        time.sleep(5)  # 单个许愿间延迟
            except Exception as e:
                log(f"{name} 创建许愿失败: {str(e)}", "ERROR")
                continue  # 单个账号失败不影响其他账号
    
    def get_active_wishes(self, client: P115Client) -> List[str]:
        """获取未完成许愿列表"""
        try:
            wishes = check_response(client.act_xys_my_desire({"type": 1}))["data"]["list"]
            return [w["id"] for w in wishes if w["status"] == 1]  # 状态1为进行中
        except:
            return []
    
    def process_aiding(self) -> Dict:
        """处理助愿流程"""
        aid_map = {}
        
        for sub_name, data in self.wish_map.items():
            aid_map[sub_name] = []
            for wish_id in data["all_wishes"]:
                try:
                    # 检查许愿状态
                    wish_info = check_response(self.main_client.act_xys_get_desire_info(wish_id))
                    if wish_info.get("data", {}).get("status") != 1:
                        continue
                    
                    # 创建助愿
                    aid_id = check_response(
                        self.main_client.act_xys_aid_desire({
                            "id": wish_id,
                            "content": "希望这本书可以帮到您",
                            "file_ids": ""
                        })
                    )["data"]["aid_id"]
                    
                    aid_map[sub_name].append((wish_id, aid_id))
                    log(f"{self.main_name} 为 {sub_name} 的许愿 {wish_id} 助愿成功")
                    time.sleep(5)  # 单个助愿间延迟
                except Exception as e:
                    log(f"助愿失败 {wish_id}: {str(e)}", "ERROR")
        
        return aid_map
    
    def process_adoption(self, aid_map: Dict):
        """处理采纳流程"""
        for sub_name, data in self.wish_map.items():
            client = data["client"]
            for wish_id in data["all_wishes"]:
                try:
                    # 获取有效助愿
                    aids = check_response(client.act_xys_desire_aid_list({"id": wish_id}))["data"]["list"]
                    valid_aids = [a["id"] for a in aids if a["status"] == 1]  # 状态1为有效助愿
                    
                    # 批量采纳
                    for aid_id in valid_aids:
                        result = check_response(client.act_xys_adopt({
                            "did": wish_id,
                            "aid": aid_id,
                            "to_cid": 0
                        }))
                        if result.get("state"):
                            log(f"{sub_name} 成功采纳许愿 {wish_id} 的助愿 {aid_id}")
                            time.sleep(3)  # 单个采纳间延迟
                except Exception as e:
                    log(f"{sub_name} 处理许愿 {wish_id} 失败: {str(e)}", "ERROR")

######################
#  日志系统（增强版）
######################
def log(msg: str, level: str = "INFO"):
    """记录带颜色标记的日志"""
    color_map = {
        "ERROR": "\033[31m",
        "WARNING": "\033[33m",
        "INFO": "\033[32m",
        "END": "\033[0m"
    }
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    colored_msg = f"{color_map.get(level, '')}[{timestamp}] [{level}] {msg}{color_map['END']}"
    print(colored_msg)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] [{level}] {msg}\n")

######################
#  主程序
######################
if __name__ == "__main__":
    try:
        config = load_config()
        
        log("启动智能流程".center(40, "="))
        checkin_all(config)
        
        wish_system = SmartWishSystem(config["main"], config["subs"])
        wish_system.full_process()
        
        log("所有流程执行完毕".center(40, "="))
    except Exception as e:
        log(f"主程序异常: {str(e)}", "ERROR")
        sys.exit(1)
    except KeyboardInterrupt:
        log("用户中断操作", "WARNING")
        sys.exit(0)
