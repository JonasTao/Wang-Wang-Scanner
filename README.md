# 🐕🐱 汪汪安全扫描器

基于 **PyQt5** 的网络安全信息收集工具。界面为可爱风格，左侧有**小狗与小猫互动打闹**的动态陪伴动画。

> ⚠️ 仅供在获得明确书面授权的前提下进行合法安全测试。
<img width="1274" height="831" alt="{6A2BDEE2-4CE7-4325-B668-F5B1D7271B10}" src="https://github.com/user-attachments/assets/983ebef4-1347-459b-a0bb-1b0291103f7c" />


## 功能模块（共 18 项）

| 分类 | 模块 |
|------|------|
| 信息搜集 | 👤 人员信息、📋 WHOIS 查询 |
| 资产发现 | 🏢 网络资产、🌐 子域名枚举、🗺️ C 段旁站 |
| DNS/邮件 | 🔐 DNS 安全 (SPF/DMARC/DKIM/AXFR) |
| 主机与端口 | 📡 存活探测、🔌 端口扫描、💻 系统检测 |
| 网络与协议 | 🌐 网络信息、🔒 SSL/TLS、📁 SMB、📶 SNMP |
| Web | 🔎 Web 指纹 (WAF/CDN/CMS)、🛡️ 漏洞扫描、📂 敏感文件、🔗 API 发现 |
| 服务风险 | ⚠️ 弱配置 (Redis/Mongo/ES/Docker 等) |

## 安装运行

```bash
cd security_scanner
pip install -r requirements.txt
python main.py
```

可选：安装 [Nmap](https://nmap.org/) 以使用 SYN 扫描与 OS 检测。

## 项目结构

```
security_scanner/
├── main.py
├── core/           # 扫描基类、后台线程
├── scanners/       # 18 个扫描器
├── ui/
│   ├── dog_companion.py  # 狗猫互动动画
│   └── panels/     # 各功能面板
└── requirements.txt
```
