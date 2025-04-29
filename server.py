"""
description  a mcp server for artemis sast tool
author       pony
date         2025.4.29
"""

from mcp.server.fastmcp import FastMCP
from pathlib import Path
import os
import requests
from mcp.server.fastmcp.prompts import base
from typing import Any


graph_server="http://127.0.0.1:8088"

mcp = FastMCP("artemis mcp server")

def send_query(url:str)->str:
    """
    将graph query请求发送到artemis graph server
    """
    res=requests.get(url=url,timeout=60)
    return res.text

def search_issue(issue_id:str)->str:
    """
    搜索issue信息
    """
    api_name="issue"
    res=send_query(url=f"{graph_server}/{api_name}?issue_id={issue_id}")
    if res:
        return res
    else:
        return "未发现相关issue"

def search_plugins(status:str)->str:
    """
    列举插件列表
    """
    api_name="plugins"
    res=send_query(url=f"{graph_server}/{api_name}?status={status}")
    return res


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
def list_support_vuln_type():
    """
    枚举支持的漏洞检出类型
    """

@mcp.tool()
def show_issue_info(issue_id:str):
    """
    根据issue_id 从artemis的数据库中查找漏洞并展示
    issue_id 是漏洞编号
    """
    res=search_issue(issue_id=issue_id)
    return res

@mcp.tool()
def show_dependency_of_current_project():
    """
    查询当前项目的依赖信息
    """

@mcp.tool()
def show_projects():
    """
    查询当前的项目列表
    """

@mcp.tool()
def show_project_info():
    """
    查询当前项目的信息
    """

import subprocess

@mcp.tool()
def build(path:str,database:str)->bool:
    """
    根据config配置文件进行编译,生成代码语义数据库
    path是待分析的源码目录
    """
    current_path=os.getcwd()
    artemis_path=f"{current_path}/artemis-scanner/Artemis.jar"
    build_properties=f"{current_path}/artemis-scanner/conf/build.properties"
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

@mcp.tool()
def list_plugins(status:str):
    """
    插件列表信息
    status 是插件启用状态，有三种状态值
        - enabled 表示启用
        - disabled 表示禁用
        - all 表示启用的和禁用的
    """
    res=search_plugins(status=status)
    print(res)
    return res


if __name__ == "__main__":
    mcp.settings.host="127.0.0.1"
    mcp.settings.port=8082
    mcp.run(transport="sse")