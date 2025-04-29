
from .server import main
import sys
import argparse
#-------------------------------------------------------------------------------------------
# artemis mcp server 模块执行入口
#-------------------------------------------------------------------------------------------
parser = argparse.ArgumentParser(description="this is a mcp server for artemis sast tool.")
parser.add_argument('-v', '--verbose', help='artemis-mcp-server-v0.1.0 ', action='store_true')
parser.add_argument('-r','--rule',type=str,help='path to rule')
parser.add_argument('-s','--server',type=str,help='mcp server host')
parser.add_argument('-p','--port',type=int,help='mcp server port')
args=parser.parse_args()
if __name__ == "__main__":
    sys.exit(main(host=args.server,port=args.port))