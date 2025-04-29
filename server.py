"""
description  a mcp server for artemis sast tool
author       pony
date         2025.4.29
"""
import os
import requests
import argparse
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("artemis mcp server")

__version__="0.1.0"

__all__ = ["list_all_flaws","list_target_vuln","build","scan"]

@mcp.tool()
def list_all_flaws(report_path:str)->list:
    """
    枚举所有artemis检出的漏洞列表
    report_path是报告的地址
    返回字段中
        - name表示漏洞名
        - checker_name 表示扫描插件名
        - level 表示漏洞等级
        - desc 表示漏洞描述
    """
    file=open(report_path)
    data=json.loads(file.read())
    ret_list=[]
    for t in data:
        ret_list.append(
            {
                "name":t['name'],
                "checker_name":t['checker_name'],
                "level":t['level'],
                "sink":t['trace'][0]
            }
        )
    return ret_list
    
@mcp.tool()
def list_target_vuln(report_path:str,vuln_type:str):
    """
    枚举指定类型的漏洞
    report_path是报告的地址
    vuln_type是漏洞类型
    返回字段中
        - name表示漏洞名
        - checker_name 表示扫描插件名
        - level 表示漏洞等级
        - desc 表示漏洞描述
    """
    file=open(report_path)
    data=json.loads(file.read())
    ret_list=[]
    for t in data:
        if t['name']==vuln_type:
            ret_list.append(
                {
                    "name":t['name'],
                    "checker_name":t['checker_name'],
                    "level":t['level'],
                    "desc":t['desc'],
                    "sink":t['trace'][0]
                }
            )
    return ret_list

@mcp.tool()
def build(path:str,database:str)->bool:
    """
    根据config配置文件进行编译,生成代码语义数据库
    path是待分析的源码目录
    """
    current_path=os.getcwd()
    artemis_path=f"{current_path}/artemis-scanner/Artemis.jar"
    build_properties=f"{path}/build.properties"
    if not os.path.exists(build_properties):
        return """请在目录下创建一个build.properties文件，文件中应该至少要配置java_home和build_cmd两个属性。例如:
        java_home = /Library/Java/JavaVirtualMachines/jdk1.8.0_151.jdk/Contents/Home
        build_cmd= mvn clean package -X -DskipTests=true
        """
    process = subprocess.Popen(['java', '-jar',artemis_path,"-p",path,"-bp",build_properties,"-od",database],stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # 实时读取输出
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            print(output.strip())
    
    # 等待进程结束
    process.wait()
    return True

import json
def get_scan_summary(report_path:str)->dict:
    """
    获取artemis的报告的概览信息
    report_path是报告的路径
    返回字段中flaws_num表示发现的漏洞总数，flaws_type表示各个漏洞漏洞类型各自发现了多少漏洞
    """
    file=open(report_path)
    data=json.loads(file.read())
    flaws_num=len(data)
    flaws_type={}
    for t in data:
        if not flaws_type.get(t['name']):
            flaws_type[t['name']]=1
        else:
            flaws_type[t['name']]+=1
    return {
        "flaws_num":flaws_num,
        "flaws_type":flaws_type
    }


@mcp.tool()
def scan(path:str,project_name:str)->str:
    """
    根据用户提供的路径进行源代码安全扫描，输出检出报告
    path待分析的源码路径
    project_name是当前的项目名，一般取当前项目的目录名
    返回字段中
        - flaws_num表示发现的漏洞总数，
        - flaws_type表示各个漏洞漏洞类型各自发现了多少漏洞
        - report_path 表示报告路径
    """
    database=f"/tmp/artemis_db/{project_name}"
    report_path=f"{database}/report.json"
    build(path=path,database=database)
    current_path=os.getcwd()
    artemis_path=f"{current_path}/artemis-scanner/Artemis.jar"
    build_properties=f"{current_path}/artemis-scanner/conf/build.properties"
    rule_path=f"{current_path}/artemis-scanner/conf/Checker.xml"
    process = subprocess.Popen(['java', '-jar',artemis_path,"-d",database,"-r",rule_path,"-bp",build_properties,"-o",report_path],stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # 实时读取输出
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            print(output.strip())
    
    # 等待进程结束
    process.wait()
    summary=get_scan_summary(report_path=report_path)
    flaws_type=""
    for k,v in summary['flaws_type'].items():
        flaws_type+=f"{k} - 共{v}个\n"
    return f"\n报告路径:{report_path}\n共发现:{summary['flaws_num']}个漏洞\n漏洞分布如下:\n{flaws_type}"

# main
def main(host:str,port:int):
    mcp.settings.host=host
    mcp.settings.port=port
    mcp.run(transport="sse")