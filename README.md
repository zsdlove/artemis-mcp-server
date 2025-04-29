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
examples:
python3 -m artemis-mcp-server -s 127.0.0.1 -p 8088
```
# config
需要在项目根目录下配置build.properties，以便于扫描器能够正常编译
example:
```
java_home = /Library/Java/JavaVirtualMachines/jdk1.8.0_151.jdk/Contents/Home
build_cmd= mvn clean package -X -DskipTests=true
```
java_home 是项目编译所需的jdk版本
build_cmd 是编译命令