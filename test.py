import server
def test_for_scan():
    server.scan(path="/Users/pony/Desktop/release/1.0.0/test/java-sec-code-master",project_name="project")
report="/tmp/artemis_db/java-sec-code-master/report.json"
summary=server.get_scan_summary(report_path=report)
flaws_type=""
for k,v in summary['flaws_type'].items():
        flaws_type+=f"{k} - 共{v}个\n"
print(f"\n报告路径:{report}\n共发现:{summary['flaws_num']}个漏洞\n漏洞分布如下:\n{flaws_type}")