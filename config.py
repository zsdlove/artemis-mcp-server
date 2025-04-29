import os
import logging
current_path=os.getcwd()
artemis_path=f"{current_path}/artemis-mcp-server/artemis-scanner/Artemis.jar"
rule_path=f"{current_path}/artemis-mcp-server/artemis-scanner/conf/Checker.xml"
artemis_db_base="/tmp/artemis_db"

# 配置日志
logging.basicConfig(level=logging.DEBUG,
                    filename='run.log',  # 日志文件名称
                    filemode='a',  # 模式，'a'表示追加，'w'表示覆盖
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')