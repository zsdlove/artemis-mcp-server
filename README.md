# artemis-mcp-server
this is a mcp server for artemis sast tool
# usage
```
命令行参数:
python3 -m artemis-mcp-server --help
pony@ponydeMBP % python3 -m artemis-mcp-server --help
usage: __main__.py [-h] [-v] [-r RULE] [-s SERVER] [-p PORT]

this is a mcp server for artemis sast tool.

options:
  -h, --help           show this help message and exit
  -v, --verbose        artemis-mcp-server-v0.1.0
  -r, --rule RULE      path to rule
  -s, --server SERVER  mcp server host
  -p, --port PORT      mcp server port
示例:
python3 -m artemis-mcp-server -s 127.0.0.1 -p 8088
```