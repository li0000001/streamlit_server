#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 导入所有需要的库
import os
import json
import random
import time
import shutil
import re
import subprocess
import platform
import uuid
from pathlib import Path
import urllib.request
import urllib.parse
import urllib.error
import ssl
import socket
import tarfile
import streamlit as st

# --- 全局常量定义 ---
# 工作目录，所有运行时文件都将存放在这里
INSTALL_DIR = Path.home() / ".agsb"
# 各种运行时文件的具体路径
SB_PID_FILE = INSTALL_DIR / "sbpid.log"
ARGO_PID_FILE = INSTALL_DIR / "sbargopid.log"
LIST_FILE = INSTALL_DIR / "list.txt"
LOG_FILE = INSTALL_DIR / "argo.log"
SB_LOG_FILE = INSTALL_DIR / "sb.log"
ALL_NODES_FILE = INSTALL_DIR / "allnodes.txt"
GEO_FILE = INSTALL_DIR / "geo.json"

# --- 辅助函数 ---

def download_file(url, target_path, silent=False):
    """下载文件，可选择是否在界面上显示错误信息。"""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(target_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        return True
    except Exception as e:
        if not silent:
            st.error(f"下载失败: {url}, 错误: {e}")
        return False

def resolve_ipv4(domain):
    """把域名解析成 IPv4 地址列表（避免客户端拿到 AAAA 后走质量差的 IPv6）。"""
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        seen = []
        for info in infos:
            ip = info[4][0]
            if ip not in seen:
                seen.append(ip)
        return seen
    except Exception:
        return []

def generate_vless_link(config):
    """根据配置字典生成 VLESS 链接字符串（WebSocket + TLS）。"""
    query = urllib.parse.urlencode({
        "type": "ws",
        "encryption": "none",
        "security": "tls",
        "sni": config.get("sni") or "",
        "host": config.get("host") or "",
        "path": "/",
        # 关键：显式声明 flow=none。
        # 新版客户端（Xray/v2rayN/Hiddify）导入 VLESS 链接时默认会加 flow=xtls-rprx-vision，
        # 而 sing-box 1.14 收到 vision 流控请求时会去找 TLS Reality 的 detour 导致握手失败(EOF)。
        "flow": "none",
        # 部分客户端依赖这个字段来正确识别 ws 传输的伪装头类型
        "headerType": "none",
    })
    name = urllib.parse.quote(config.get("ps") or "", safe="")
    # IPv6 地址在 URL 中必须用方括号包裹，否则端口解析会出错
    address = str(config.get("add") or "")
    if ":" in address and not address.startswith("["):
        address = f"[{address}]"
    return (f"vless://{config.get('id')}@{address}:{config.get('port')}"
            f"?{query}#{name}")

def get_tunnel_domain():
    """从argo日志文件中尝试读取Cloudflare临时隧道域名。"""
    for _ in range(15): # 最多等待30秒
        if LOG_FILE.exists():
            try:
                log_content = LOG_FILE.read_text(encoding="utf-8", errors="ignore")
                match = re.search(r'https://([a-zA-Z0-9.-]+\.trycloudflare\.com)', log_content)
                if match: return match.group(1)
            except Exception: pass
        time.sleep(2)
    return None

def stop_services():
    """停止所有由本脚本启动的后台服务进程。"""
    for pid_file in [SB_PID_FILE, ARGO_PID_FILE]:
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, 9) # 强制终止进程
            except (ValueError, ProcessLookupError, FileNotFoundError): pass
            finally: pid_file.unlink(missing_ok=True) # 删除PID文件
    # 作为最后的保险措施，按名字查找并杀死进程
    subprocess.run("pkill -9 -f 'sing-box run'", shell=True, capture_output=True)
    subprocess.run("pkill -9 -f 'cloudflared tunnel'", shell=True, capture_output=True)

def is_service_running():
    """通过检查PID文件和进程是否存在，来判断核心服务是否在运行。"""
    if not SB_PID_FILE.exists() or not ARGO_PID_FILE.exists():
        return False
    try:
        sb_pid = int(SB_PID_FILE.read_text().strip())
        argo_pid = int(ARGO_PID_FILE.read_text().strip())
        # 在类Unix系统中，os.kill(pid, 0) 不会杀死进程，而是检查进程是否存在
        os.kill(sb_pid, 0)
        os.kill(argo_pid, 0)
        return True
    except (ValueError, ProcessLookupError, FileNotFoundError):
        # 如果PID文件内容错误、进程不存在或文件找不到，都视为服务未运行
        return False

# --- 出口IP归属地 ---

# 国家代码 -> 中文名（未收录的回退到接口返回的原始名称）
COUNTRY_CN = {
    "AF": "阿富汗", "AL": "阿尔巴尼亚", "DZ": "阿尔及利亚", "AR": "阿根廷", "AM": "亚美尼亚",
    "AU": "澳大利亚", "AT": "奥地利", "AZ": "阿塞拜疆", "BH": "巴林", "BD": "孟加拉国",
    "BY": "白俄罗斯", "BE": "比利时", "BZ": "伯利兹", "BO": "玻利维亚", "BA": "波黑",
    "BR": "巴西", "BN": "文莱", "BG": "保加利亚", "KH": "柬埔寨", "CM": "喀麦隆",
    "CA": "加拿大", "CL": "智利", "CN": "中国", "CO": "哥伦比亚", "CR": "哥斯达黎加",
    "HR": "克罗地亚", "CY": "塞浦路斯", "CZ": "捷克", "DK": "丹麦", "DO": "多米尼加",
    "EC": "厄瓜多尔", "EG": "埃及", "EE": "爱沙尼亚", "ET": "埃塞俄比亚", "FI": "芬兰",
    "FR": "法国", "GE": "格鲁吉亚", "DE": "德国", "GH": "加纳", "GR": "希腊",
    "GT": "危地马拉", "HK": "中国香港", "HN": "洪都拉斯", "HU": "匈牙利", "IS": "冰岛",
    "IN": "印度", "ID": "印度尼西亚", "IR": "伊朗", "IQ": "伊拉克", "IE": "爱尔兰",
    "IL": "以色列", "IT": "意大利", "CI": "科特迪瓦", "JM": "牙买加", "JP": "日本",
    "JO": "约旦", "KZ": "哈萨克斯坦", "KE": "肯尼亚", "KW": "科威特", "KG": "吉尔吉斯斯坦",
    "LA": "老挝", "LV": "拉脱维亚", "LB": "黎巴嫩", "LT": "立陶宛", "LU": "卢森堡",
    "MO": "中国澳门", "MG": "马达加斯加", "MY": "马来西亚", "MT": "马耳他", "MU": "毛里求斯",
    "MX": "墨西哥", "MD": "摩尔多瓦", "MC": "摩纳哥", "MN": "蒙古", "ME": "黑山",
    "MA": "摩洛哥", "MM": "缅甸", "NA": "纳米比亚", "NP": "尼泊尔", "NL": "荷兰",
    "NZ": "新西兰", "NI": "尼加拉瓜", "NG": "尼日利亚", "KP": "朝鲜", "MK": "北马其顿",
    "NO": "挪威", "OM": "阿曼", "PK": "巴基斯坦", "PA": "巴拿马", "PY": "巴拉圭",
    "PE": "秘鲁", "PH": "菲律宾", "PL": "波兰", "PT": "葡萄牙", "PR": "波多黎各",
    "QA": "卡塔尔", "RO": "罗马尼亚", "RU": "俄罗斯", "SA": "沙特阿拉伯", "RS": "塞尔维亚",
    "SG": "新加坡", "SK": "斯洛伐克", "SI": "斯洛文尼亚", "ZA": "南非", "KR": "韩国",
    "ES": "西班牙", "LK": "斯里兰卡", "SE": "瑞典", "CH": "瑞士", "SY": "叙利亚",
    "TW": "中国台湾", "TJ": "塔吉克斯坦", "TZ": "坦桑尼亚", "TH": "泰国", "TN": "突尼斯",
    "TR": "土耳其", "TM": "土库曼斯坦", "UG": "乌干达", "UA": "乌克兰", "AE": "阿联酋",
    "GB": "英国", "US": "美国", "UY": "乌拉圭", "UZ": "乌兹别克斯坦", "VE": "委内瑞拉",
    "VN": "越南", "YE": "也门", "ZM": "赞比亚", "ZW": "津巴布韦",
}

def get_exit_country():
    """查询本机出口IP及其归属国家，结果缓存到 GEO_FILE。返回 (国家中文名, 出口IP)。"""
    if GEO_FILE.exists():
        try:
            saved = json.loads(GEO_FILE.read_text(encoding="utf-8"))
            if saved.get("country"):
                return saved["country"], saved.get("ip", "")
        except Exception:
            pass

    # 三个备用接口，依次尝试（都不要求 API Key）
    apis = [
        ("https://ipwho.is/",       lambda d: (d.get("country"), d.get("country_code"), d.get("ip"))),
        ("https://ipapi.co/json/",  lambda d: (d.get("country_name"), d.get("country_code"), d.get("ip"))),
        ("http://ip-api.com/json/", lambda d: (d.get("country"), d.get("countryCode"), d.get("query"))),
    ]
    for url, pick in apis:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            country_raw, code, ip = pick(data)
            if not country_raw and not code:
                continue
            cn = COUNTRY_CN.get((code or "").upper()) or country_raw
            try:
                GEO_FILE.write_text(
                    json.dumps({"country": cn, "code": code or "", "ip": ip or ""}, ensure_ascii=False),
                    encoding="utf-8")
            except Exception:
                pass
            return cn, ip or ""
        except Exception:
            continue
    return None, None

# --- 核心逻辑 ---

def generate_all_configs(domain, uuid_str, port_vm_ws):
    """生成所有节点链接和配置文件，并返回用于UI显示的文本。"""
    # 让 Streamlit 服务端查询自己的出口IP归属地，用国家名做节点名前缀
    country, exit_ip = get_exit_country()
    region = country or "未知"
    protocol = "VLWS-TLS"
    all_links = []
    # 使用一些Cloudflare的优选IP来生成节点（只保留 IPv4/域名，避免 IPv6 劣质路由导致连接失败）
    cf_ips_tls = {
            # 下面是 Cloudflare 官方公告的 IPv4 网段起点，纯 IPv4 字面量 + 443，
            # 不依赖客户端本地 DNS 解析，最稳定。故意不用 www.visa.com 这类"掩护域名"：
            # 它们每次要本地解析，解析到被污染/被限速的 IP 时就会随机失败。
            "104.16.0.0": "443",
            "104.17.0.0": "443",
            "104.18.0.0": "443",
            "104.19.0.0": "443",
            "104.20.0.0": "443",
            "104.21.0.0": "443",
            "172.64.0.0": "443",
            "172.65.0.0": "443",
            "172.66.0.0": "443",
            "172.67.0.0": "443"}
    # 再过滤一遍：地址里带冒号的是 IPv6，直接跳过（IPv6 路由不佳时会导致测试 -1）
    cf_ips_v4 = {ip: port for ip, port in cf_ips_tls.items() if ":" not in str(ip)}
    # 最稳的 Direct 节点排在最前（Cloudflare 会按客户端网络自动选就近入点）
    all_links.append(generate_vless_link({"ps": f"{region}-{protocol}-1-Direct", "add": domain, "port": "443", "id": uuid_str, "host": domain, "sni": domain}))
    # 服务器端提前把域名钉成 IPv4：客户端如果拿到 AAAA 就会走 IPv6，
    # 而很多宽带的 IPv6 路由质量很差，会导致这个节点永远连不上。
    for i, ip in enumerate(resolve_ipv4(domain)[:3], start=2):
        all_links.append(generate_vless_link({"ps": f"{region}-{protocol}-{i}-Direct4", "add": ip, "port": "443", "id": uuid_str, "host": domain, "sni": domain}))
    # 节点名格式：国家-协议名称-序号
    idx = 2 + len(resolve_ipv4(domain)[:3])
    for ip, port in cf_ips_v4.items():
        all_links.append(generate_vless_link({"ps": f"{region}-{protocol}-{idx}", "add": ip, "port": port, "id": uuid_str, "host": domain, "sni": domain}))
        idx += 1
    
    # 将所有链接写入文件，以便下次直接读取
    ALL_NODES_FILE.write_text("\n".join(all_links) + "\n", encoding="utf-8")

    # 准备要在UI上显示的输出文本
    list_output_text = f"""
✅ **服务已启动**
---
- **域名 (Domain):** `{domain}`
- **出口IP:** `{exit_ip or '查询失败'}`
- **归属地:** `{region}`
- **UUID:** `{uuid_str}`
- **本地端口:** `{port_vm_ws}`
- **WebSocket路径:** `/`
---
**VLESS 链接 (可复制):**
""" + "\n".join(all_links)
    
    # 将UI文本也写入文件
    LIST_FILE.write_text(list_output_text, encoding="utf-8")
    return list_output_text

def start_services(uuid_str, port_vm_ws, custom_domain, argo_token, silent=False):
    """核心函数：安装并启动服务，可选择静默模式。"""
    
    if not silent:
        st.info("🔄 正在启动/重启服务...")

    stop_services()
    
    try:
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        
        uuid_str = uuid_str or str(uuid.uuid4())
        port_vm_ws = port_vm_ws or random.randint(10000, 65535)

        # 定义依赖项及其下载逻辑
        arch = "amd64" if "x86_64" in platform.machine().lower() else "arm64"
        singbox_path = INSTALL_DIR / "sing-box"
        cloudflared_path = INSTALL_DIR / "cloudflared"

        # 封装下载和安装过程
        def install_dependencies():
            if not singbox_path.exists():
                sb_version, sb_name_actual = "1.14.2", f"sing-box-1.14.2-linux-{arch}"
                tar_path = INSTALL_DIR / "sing-box.tar.gz"
                if not download_file(f"https://github.com/SagerNet/sing-box/releases/download/v{sb_version}/{sb_name_actual}.tar.gz", tar_path, silent):
                    return False, "sing-box 下载失败。"
                with tarfile.open(tar_path, "r:gz") as tar: tar.extractall(path=INSTALL_DIR)
                shutil.move(INSTALL_DIR / sb_name_actual / "sing-box", singbox_path)
                shutil.rmtree(INSTALL_DIR / sb_name_actual); tar_path.unlink(); os.chmod(singbox_path, 0o755)

            if not cloudflared_path.exists():
                cf_arch = "amd64" if arch == "amd64" else "arm"
                if not download_file(f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}", cloudflared_path, silent):
                    return False, "cloudflared 下载失败。"
                os.chmod(cloudflared_path, 0o755)
            return True, ""

        # 根据是否为静默模式，决定是否显示 spinner
        if not silent:
            with st.spinner("正在检查并安装依赖 (sing-box, cloudflared)..."):
                success, msg = install_dependencies()
                if not success: return False, msg
        else:
            success, msg = install_dependencies()
            if not success: return False, msg

        # 创建 sing-box 配置文件
        # 注意：不要加 "sniff" 等旧版 inbound 字段——sing-box 1.13+ 会直接拒绝该配置并退出
        sb_config = {"log": {"level": "info"},
                     "inbounds": [{"type": "vless", "tag": "vless-in", "listen": "127.0.0.1",
                                   "listen_port": port_vm_ws,
                                   "users": [{"uuid": uuid_str}],
                                   "transport": {"type": "ws", "path": "/"}}],
                     "outbounds": [{"type": "direct"}]}
        (INSTALL_DIR / "sb.json").write_text(json.dumps(sb_config, indent=2))
        
        # 启动 sing-box 和 cloudflared 进程
        with open(SB_LOG_FILE, "w") as sb_log, open(LOG_FILE, "w") as cf_log:
            sb_process = subprocess.Popen([str(singbox_path), 'run', '-c', 'sb.json'], cwd=INSTALL_DIR, stdout=sb_log, stderr=subprocess.STDOUT)
            SB_PID_FILE.write_text(str(sb_process.pid))
            
            cf_cmd = [str(cloudflared_path), 'tunnel', '--no-autoupdate', 'run', '--token', argo_token] if argo_token else [str(cloudflared_path), 'tunnel', '--no-autoupdate', '--url', f'http://localhost:{port_vm_ws}', '--protocol', 'http2']
            cf_process = subprocess.Popen(cf_cmd, cwd=INSTALL_DIR, stdout=cf_log, stderr=subprocess.STDOUT)
            ARGO_PID_FILE.write_text(str(cf_process.pid))

        # 等待并获取域名
        time.sleep(5)

        # 验证进程没有启动即退出：配置不兼容时 sing-box 会立刻报错退出，
        # 以前不检查会让界面显示"服务已启动"但所有节点实际都是 -1
        def _log_tail(path, lines=12):
            try:
                return "\n".join(path.read_text(encoding="utf-8", errors="ignore").splitlines()[-lines:])
            except Exception:
                return "(无法读取日志)"

        if sb_process.poll() is not None:
            stop_services()
            return False, (f"sing-box 启动失败 (exit code {sb_process.returncode})，"
                           f"配置不兼容或端口被占用。日志最后几行：\n{_log_tail(SB_LOG_FILE)}")
        if cf_process.poll() is not None:
            stop_services()
            return False, (f"cloudflared 启动失败 (exit code {cf_process.returncode})，"
                           f"请检查 ARGO_TOKEN。日志最后几行：\n{_log_tail(LOG_FILE)}")

        final_domain = custom_domain or (get_tunnel_domain() if not argo_token else None)
        if not final_domain:
            return False, "未能确定隧道域名。请检查日志 (`.agsb/argo.log`)。"

        links_output = generate_all_configs(final_domain, uuid_str, port_vm_ws)
        return True, links_output
    
    except Exception as e:
        return False, f"处理过程中发生意外错误: {e}"

def uninstall_services():
    """卸载服务，清理所有运行时文件和进程。"""
    stop_services()
    if INSTALL_DIR.exists(): shutil.rmtree(INSTALL_DIR)
    st.success("✅ 卸载完成。所有运行时文件和进程已清除。")
    st.session_state.clear()

# --- UI 渲染函数 ---

def probe_tunnel(domain):
    """服务器自己探测隧道是否真的可用（不依赖任何客户端）。"""
    if not domain:
        return "未提供域名，无法探测"
    url = f"https://{domain}/"
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
            return f"✅ 隧道可达！HTTP {resp.status}（直接访问 {url} 成功返回）"
    except urllib.error.HTTPError as e:
        # Cloudflare 会返回错误页面，HTTP 错误码本身说明隧道是通的（能到 CF 边缘）
        if e.code == 530:
            return f"⚠️ HTTP 530：域名未启用代理或 DNS 记录有问题（能连到 CF，但不是隧道）"
        if e.code == 404:
            return f"✅ 隧道可达！HTTP 404 说明请求已到达 Cloudflare（后端无此路径属正常）"
        return f"⚠️ HTTP {e.code}：能到达 Cloudflare 边缘，但后端返回错误"
    except Exception as e:
        return f"❌ 探测失败: {type(e).__name__}: {e}"

def get_diagnostics(domain=""):
    """收集运行状态、进程、端口、配置和日志尾部，用于排查节点全部 -1 的问题。"""
    out = ["=== 运行诊断 ==="]
    singbox_path = INSTALL_DIR / "sing-box"
    cloudflared_path = INSTALL_DIR / "cloudflared"

    # 服务器端主动探测隧道（最权威的判断依据）
    out.append("--- 服务器端隧道自检 ---")
    out.append(probe_tunnel(domain))

    # 二进制与版本
    for label, p in (("sing-box", singbox_path), ("cloudflared", cloudflared_path)):
        if p.exists():
            out.append(f"[OK] {label} 二进制存在: {p} ({p.stat().st_size} 字节)")
            try:
                if label == "sing-box":
                    r = subprocess.run([str(p), "version"], cwd=INSTALL_DIR,
                                       capture_output=True, text=True, timeout=10)
                    out.append(f"     版本: {(r.stdout or r.stderr).strip()[:300]}")
            except Exception as e:
                out.append(f"     版本查询失败: {e}")
        else:
            out.append(f"[缺失] {label} 二进制不存在: {p}")

    # 进程存活
    for label, pid_file, proc_name in (("sing-box", SB_PID_FILE, "sing-box"),
                                       ("cloudflared", ARGO_PID_FILE, "cloudflared")):
        if not pid_file.exists():
            out.append(f"[未启动] {label}: PID 文件不存在")
            continue
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, 0)
            out.append(f"[运行中] {label}: PID {pid}")
        except Exception as e:
            out.append(f"[已死亡] {label}: PID 文件写着 {pid_file.read_text().strip()}，但进程不存在 ({e})")

    # 实际进程列表（确认是否有孤儿进程占着端口）
    try:
        r = subprocess.run("ps aux | grep -E 'sing-box|cloudflared' | grep -v grep",
                           shell=True, capture_output=True, text=True, timeout=10)
        out.append("--- ps aux ---")
        out.append((r.stdout or "(没有匹配进程)").strip()[:1500])
    except Exception as e:
        out.append(f"ps 执行失败: {e}")

    # 配置内容
    cfg = INSTALL_DIR / "sb.json"
    if cfg.exists():
        out.append("--- 当前 sb.json ---")
        out.append(cfg.read_text(encoding="utf-8", errors="ignore")[:1000])

    # 日志尾部
    for label, path in (("sing-box 日志 (sb.log)", SB_LOG_FILE), ("cloudflared 日志 (argo.log)", LOG_FILE)):
        if path.exists():
            tail = "\n".join(path.read_text(encoding="utf-8", errors="ignore").splitlines()[-20:])
            out.append(f"--- {label} 最后 20 行 ---")
            out.append(tail if tail.strip() else "(空)")
        else:
            out.append(f"[缺失] {label}: {path}")

    # cloudflared 隧道注册状态（关键：precheck 通过 ≠ 隧道已连上）
    if LOG_FILE.exists():
        try:
            lines = LOG_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()
            keys = ("registered tunnel connection", "unregistered tunnel connection",
                    "failed", "error", "retry", "reconnect", "unable")
            hits = [ln for ln in lines if any(k in ln.lower() for k in keys)]
            out.append(f"--- cloudflared 隧道注册/错误关键行（共 {len(lines)} 行日志）---")
            out.append("\n".join(hits[-25:]) if hits else "(没有任何注册或错误记录 —— 隧道可能从未连上 Cloudflare！)")
        except Exception as e:
            out.append(f"argo.log 解析失败: {e}")

    return "\n".join(out)

def render_main_ui(config):
    """渲染主控制面板。"""
    st.set_page_config(page_title="部署工具", layout="wide")
    st.header("⚙️ 服务管理面板")

    st.subheader("控制操作")
    c1, c2, c3, c4 = st.columns(4)
    
    if c1.button("🚀 强制重启服务", type="primary", use_container_width=True):
        # 手动点击按钮时，调用非静默模式，让用户看到反馈
        success, message = start_services(config["uuid_str"], config["port_vm_ws"], config["custom_domain"], config["argo_token"], silent=False)
        if success:
            st.session_state.output = message
        else:
            st.error(f"操作失败: {message}")
            st.session_state.output = message
        st.rerun()

    if c2.button("❌ 永久卸载服务", use_container_width=True):
        with st.spinner("正在执行卸载..."):
            uninstall_services()
        st.rerun()
    
    if c3.button("📄 显示/刷新节点信息", use_container_width=True):
        if LIST_FILE.exists():
            st.session_state.output = LIST_FILE.read_text(encoding="utf-8")
        else:
            st.session_state.output = "节点信息文件不存在，请先启动服务。"
        st.rerun()

    if c4.button("🔍 运行环境诊断", use_container_width=True):
        st.session_state.output = get_diagnostics(config.get("custom_domain", ""))
        st.rerun()
    
    # 优先从会话状态中读取输出，如果为空则尝试从文件读取
    output_to_show = st.session_state.get('output', '')
    if not output_to_show and LIST_FILE.exists():
        output_to_show = LIST_FILE.read_text(encoding="utf-8")
        
    if output_to_show:
        st.subheader("节点信息")
        st.code(output_to_show)

def render_login_ui(secret_key):
    """渲染伪装的天气查询登录界面。"""
    st.set_page_config(page_title="天气查询", layout="centered")
    st.title("🌦️ 实时天气查询")
    city = st.text_input("请输入城市名或秘密口令：", "")
    if st.button("查询天气"):
        if city == secret_key:
            st.session_state.authenticated = True
            st.rerun()
        else:
            with st.spinner(f"正在查询 {city} 的天气..."): time.sleep(1); st.error("查询失败，请检查城市名是否正确。")

def main():
    """主应用逻辑：先执行后台自愈，再根据登录状态渲染UI。"""
    st.session_state.setdefault('authenticated', False)
    st.session_state.setdefault('output', "")
    
    try:
        secret_key = st.secrets["SECRET_KEY"]
        config = {
            "uuid_str": st.secrets.get("UUID_STR", ""),
            "port_vm_ws": st.secrets.get("PORT_VM_WS", 0),
            "custom_domain": st.secrets.get("CUSTOM_DOMAIN", ""),
            "argo_token": st.secrets.get("ARGO_TOKEN", "")
        }
    except KeyError:
        st.error("严重错误：未在 Secrets 中找到 'SECRET_KEY'。")
        st.info("请确保您已在 Streamlit Cloud 的设置中添加了名为 'SECRET_KEY' 的密钥。")
        return

    # --- 核心自愈逻辑 ---
    # 在渲染任何UI之前，先检查服务状态。如果服务未运行，就以“静默模式”在后台启动它。
    if not is_service_running():
        start_services(
            config["uuid_str"], config["port_vm_ws"], 
            config["custom_domain"], config["argo_token"], 
            silent=True
        )
        
    # --- UI渲染逻辑 ---
    # 后台任务处理完毕后，才开始决定显示哪个页面
    if st.session_state.authenticated:
        # 如果已登录，显示主控制面板
        render_main_ui(config)
    else:
        # 如果未登录，显示伪装的天气查询页面
        render_login_ui(secret_key)

if __name__ == "__main__":
    main()
