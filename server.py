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
def list_all_flaws():
    """
    枚举所有artemis检出的漏洞列表
    """
    
@mcp.tool()
def list_target_vuln(vuln:str):
    """
    枚举指定类型的漏洞
    """

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

import config
@mcp.tool()
def scan(config:str):
    """
    根据config配置文件进行编译扫描
    """
    pass

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