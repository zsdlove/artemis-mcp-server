# artemis-mcp-server
this is a mcp server for artemis sast tool
# usage
```bash
command args:
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
Example:
python3 -m artemis-mcp-server -s 127.0.0.1 -p 8088
```
# config
the config build.properties needs to be configured in the root directory of the project so that the scanner can compile properly.
```bash
Example:
java_home = /Library/Java/JavaVirtualMachines/jdk1.8.0_151.jdk/Contents/Home
build_cmd= mvn clean package -X -DskipTests=true
```