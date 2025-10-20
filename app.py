#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 导入所有需要的库
import os
import json
import random
import time
import shutil
import re
import base64
import socket
import subprocess
import platform
import uuid
from pathlib import Path
import urllib.request
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

def generate_vmess_link(config):
    """根据配置字典生成Vmess链接字符串。"""
    vmess_obj = {
        "v": "2", "ps": config.get("ps"), "add": config.get("add"), "port": str(config.get("port")),
        "id": config.get("id"), "aid": "0", "scy": "auto", "net": "ws", "type": "none",
        "host": config.get("host"), "path": "/", "tls": "tls", "sni": config.get("sni")
    }
    vmess_str = json.dumps(vmess_obj, separators=(',', ':'))
    return f"vmess://{base64.b64encode(vmess_str.encode('utf-8')).decode('utf-8').rstrip('=')}"

def get_tunnel_domain():
    """从argo日志文件中尝试读取Cloudflare临时隧道域名。"""
    for _ in range(15): # 最多等待30秒
        if LOG_FILE.exists():
            try:
                log_content = LOG_FILE.read_text()
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

# --- 核心逻辑 ---

def generate_all_configs(domain, uuid_str, port_vm_ws):
    """生成所有节点链接和配置文件，并返回用于UI显示的文本。"""
    hostname = socket.gethostname()[:10]
    all_links = []
    # 使用一些Cloudflare的优选IP来生成节点
    cf_ips_tls = {"104.16.0.0": "443", "104.17.0.0": "8443", "104.18.0.0": "2053"}
    for ip, port in cf_ips_tls.items():
        all_links.append(generate_vmess_link({"ps": f"VMWS-TLS-{hostname}-{ip.split('.')[2]}-{port}", "add": ip, "port": port, "id": uuid_str, "host": domain, "sni": domain}))
    all_links.append(generate_vmess_link({"ps": f"VMWS-TLS-Direct-{hostname}", "add": domain, "port": "443", "id": uuid_str, "host": domain, "sni": domain}))
    
    # 将所有链接写入文件，以便下次直接读取
    ALL_NODES_FILE.write_text("\n".join(all_links) + "\n")

    # 准备要在UI上显示的输出文本
    list_output_text = f"""
✅ **服务已启动**
---
- **域名 (Domain):** `{domain}`
- **UUID:** `{uuid_str}`
- **本地端口:** `{port_vm_ws}`
- **WebSocket路径:** `/`
---
**Vmess 链接 (可复制):**
""" + "\n".join(all_links)
    
    # 将UI文本也写入文件
    LIST_FILE.write_text(list_output_text)
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
                sb_version, sb_name_actual = "1.9.0-beta.11", f"sing-box-1.9.0-beta.11-linux-{arch}"
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
        sb_config = {"log": {"level": "info"}, "inbounds": [{"type": "vmess", "tag": "vmess-in", "listen": "127.0.0.1", "listen_port": port_vm_ws, "sniff": True, "users": [{"uuid": uuid_str, "alterId": 0}], "transport": {"type": "ws", "path": "/"}}], "outbounds": [{"type": "direct"}]}
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

def render_main_ui(config):
    """渲染主控制面板。"""
    st.set_page_config(page_title="部署工具", layout="wide")
    st.header("⚙️ 服务管理面板")

    st.subheader("控制操作")
    c1, c2, c3 = st.columns(3)
    
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
            st.session_state.output = LIST_FILE.read_text()
        else:
            st.session_state.output = "节点信息文件不存在，请先启动服务。"
        st.rerun()
    
    # 优先从会话状态中读取输出，如果为空则尝试从文件读取
    output_to_show = st.session_state.get('output', '')
    if not output_to_show and LIST_FILE.exists():
        output_to_show = LIST_FILE.read_text()
        
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