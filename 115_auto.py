# encoding: utf-8

"""
115综合自动化脚本（支持配置文件）
功能：全账号签到 → 许愿树流程（小号许愿 → 主号助愿 → 小号采纳）
"""

__version__ = "3.1.0"

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, List

from p115client import P115Client, check_response

# 日志文件路径
LOG_FILE = "115_auto_operation.log"

class Logger:
    """日志记录器"""
    
    def __init__(self, log_file: str):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log(self, message: str, level: str = "INFO", console: bool = True):
        """记录带时间戳的日志"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")
        
        if console:
            print(log_entry)

logger = Logger(LOG_FILE).log

def load_config_from_file(config_path: str) -> Dict:
    """从指定路径加载配置文件"""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger(f"配置文件加载失败: {str(e)}", "ERROR")
        sys.exit(1)

def checkin_single(cookies: Dict) -> bool:
    """执行单个账号签到"""
    try:
        client = P115Client(cookies, check_for_relogin=True)
        result = client.user_points_sign_post()
        if result.get("state"):
            days = result.get("data", {}).get("continuous_day", 0)
            logger(f"签到成功，已连续签到{days}天")
            return True
        logger(f"签到失败: {result.get('message')}", "WARNING")
        return False
    except Exception as e:
        logger(f"签到异常: {str(e)}", "ERROR")
        return False

def checkin_all(config: Dict):
    """执行全部账号签到"""
    accounts = [config["wish_main"]] + config["wish_subs"]
    total = len(accounts)
    success = 0
    
    logger(f"开始签到任务，共 {total} 个账号")
    for idx, account in enumerate(accounts, 1):
        name = account.get("name", f"账号{idx}")
        logger(f"正在签到 ({idx}/{total}): {name}")
        if checkin_single(account["cookies"]):
            success += 1
        time.sleep(10)  # 账号间间隔
    
    logger(f"签到完成，成功 {success}/{total} 个账号")
    return success == total

class WishManager:
    """许愿树操作管理器"""
    
    def __init__(self, main_cookies: Dict, sub_cookies: List[Dict]):
        self.main_client = P115Client(main_cookies, check_for_relogin=True)
        self.sub_clients = [P115Client(sub["cookies"], check_for_relogin=True) for sub in sub_cookies]
    
    def wish_workflow(self, test_mode: bool = False):
        """完整的许愿工作流程"""
        total_subs = len(self.sub_clients)
        success_count = 0
        
        for idx, sub_client in enumerate(self.sub_clients, 1):
            try:
                # 小号许愿
                wish_id = self.create_wish(sub_client)
                logger(f"({idx}/{total_subs}) 小号许愿成功，ID: {wish_id}")
                
                # 增加 120 秒延迟
                logger(f"等待 120 秒后进行助愿...")
                time.sleep(120)
                
                # 主号助愿
                aid_id = self.create_aid(wish_id)
                logger(f"主号助愿成功，ID: {aid_id}")
                
                # 增加 120 秒延迟
                logger(f"等待 120 秒后进行采纳...")
                time.sleep(120)
                
                # 小号采纳
                if self.adopt_aid(sub_client, wish_id, aid_id, test_mode):
                    success_count += 1
                
                # 增加 120 秒延迟（为下一个账号做准备）
                logger(f"等待 120 秒后处理下一个账号...")
                time.sleep(120)
                
            except Exception as e:
                logger(f"流程异常: {str(e)}", "ERROR")
        
        logger(f"许愿任务完成，成功 {success_count}/{total_subs} 个账号")
        return success_count
    
    @staticmethod
    def create_wish(client: P115Client) -> str:
        """创建许愿"""
        return check_response(client.act_xys_wish(
            {"rewardSpace": 5, "content": "求一本钢铁是怎样炼成得书"}
        ))["data"]["xys_id"]
    
    def create_aid(self, wish_id: str) -> str:
        """主号创建助愿"""
        check_response(self.main_client.act_xys_get_desire_info(wish_id))
        return check_response(
            self.main_client.act_xys_aid_desire({
                "id": wish_id, 
                "content": "希望这本书可以帮到你", 
                "file_ids": ""
            })
        )["data"]["aid_id"]
    
    @staticmethod
    def adopt_aid(client: P115Client, wish_id: str, aid_id: str, test_mode: bool) -> bool:
        """采纳助愿"""
        if test_mode:
            logger("[测试模式] 跳过采纳操作", "DEBUG")
            return True
        
        result = check_response(client.act_xys_adopt({
            "did": wish_id, 
            "aid": aid_id, 
            "to_cid": 0
        }))
        return result.get("state", False)

def main():
    parser = argparse.ArgumentParser(description="115综合自动化工具")
    parser.add_argument("--config", type=str, help="配置文件路径")
    parser.add_argument("--skip-checkin", action="store_true", help="跳过签到步骤")
    parser.add_argument("--skip-wish", action="store_true", help="跳过许愿步骤")
    parser.add_argument("-t", "--test", action="store_true", help="测试模式（不执行实际采纳）")
    args = parser.parse_args()

    config = load_config_from_file(args.config) if args.config else load_config()
    
    # 执行签到流程
    if not args.skip_checkin:
        logger("开始执行签到流程".center(50, "="))
        checkin_all(config)
    
    # 执行许愿流程
    if not args.skip_wish:
        logger("开始执行许愿流程".center(50, "="))
        try:
            manager = WishManager(
                main_cookies=config["wish_main"]["cookies"],
                sub_cookies=config["wish_subs"]
            )
            manager.wish_workflow(args.test)
        except Exception as e:
            logger(f"许愿流程初始化失败: {str(e)}", "ERROR")
    
    logger("全部任务执行完成".center(50, "="))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger("用户中断操作", "WARNING")
        sys.exit(1)
