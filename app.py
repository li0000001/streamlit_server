#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Streamlit + sing-box + Cloudflare 命名隧道管理面板。

仅支持 Linux。
必须设置 SECRET_KEY、UUID_STR、ARGO_TOKEN、CUSTOM_DOMAIN。
默认监听端口 55555，监控端口 55556。

注意：
1. Cloudflare 源站地址必须手动设置为 http://127.0.0.1:55555。
2. 自动检查仅在已登录页面会话活动时执行。
3. 不保证平台休眠期间服务继续运行。
4. 本地握手成功不代表完整代理链路成功。
"""

import base64
import hashlib
import hmac
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import uuid

from collections import deque
from pathlib import Path
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

import psutil
import streamlit as st
from filelock import FileLock, Timeout


# ============================================================
# 路径与锁
# ============================================================

ROOT = Path.home() / ".agsb"
ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)

LOCK = FileLock(str(ROOT / "manager.lock"), timeout=1)

PAUSED_FILE = ROOT / "paused"
SB_CONFIG_FILE = ROOT / "sb.json"
ATTEMPTS_FILE = ROOT / "attempts.json"
ERROR_FILE = ROOT / "last_error.txt"


# ============================================================
# 文件与日志
# ============================================================

def atomic_text(path, text):
    """原子写入文件，避免读取到不完整内容。"""
    fd, filename = tempfile.mkstemp(dir=ROOT, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(filename, 0o600)
        os.replace(filename, path)
    finally:
        Path(filename).unlink(missing_ok=True)


def read_json(path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def log_event(message):
    with (ROOT / "manager.log").open("a", encoding="utf-8") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"{timestamp} {message}\n")


def tail_log(path, lines=80):
    try:
        with path.open(encoding="utf-8", errors="replace") as f:
            return "".join(deque(f, maxlen=lines))
    except OSError:
        return "暂无日志"


def redact(text, cfg):
    for key in ("token", "secret", "uuid"):
        value = cfg.get(key, "")
        if value:
            text = text.replace(value, "[已隐藏]")
    return re.sub(r"vless://[^\s]+", "[节点链接已隐藏]", text)


# ============================================================
# 配置
# ============================================================

def load_config():
    if platform.system() != "Linux":
        raise ValueError("此版本仅支持 Linux 部署环境。")

    secret = str(st.secrets.get("SECRET_KEY", "")).strip()
    token = str(st.secrets.get("ARGO_TOKEN", "")).strip()
    uid = str(st.secrets.get("UUID_STR", "")).strip()
    domain = str(st.secrets.get("CUSTOM_DOMAIN", "")).strip().lower()

    if not all((secret, token, uid, domain)):
        raise ValueError(
            "请设置 SECRET_KEY、UUID_STR、ARGO_TOKEN、CUSTOM_DOMAIN。"
        )

    if len(secret) < 16:
        raise ValueError("SECRET_KEY 至少需要 16 个字符。")

    try:
        uid = str(uuid.UUID(uid))
    except ValueError as exc:
        raise ValueError("UUID_STR 不是有效 UUID。") from exc

    labels = domain.split(".")
    label_pattern = r"?:[a-z0-9-]{0,61}[a-z0-9]?"

    if (
        len(domain) > 253
        or len(labels) < 2
        or any(not re.fullmatch(label_pattern, label) for label in labels)
    ):
        raise ValueError(
            "CUSTOM_DOMAIN 只填写有效域名，不带 https://、端口或路径。"
        )

    port = int(st.secrets.get("PORT_VM_WS", 55555))
    metrics_port = int(st.secrets.get("METRICS_PORT", 55556))

    if not (
        1024 <= port <= 65535
        and 1024 <= metrics_port <= 65535
        and port != metrics_port
    ):
        raise ValueError(
            "服务端口和监控端口必须不同，范围为 1024 至 65535。"
        )

    protocol = str(st.secrets.get("TUNNEL_PROTOCOL", "http2")).strip()
    if protocol not in ("http2", "quic", "auto"):
        raise ValueError("TUNNEL_PROTOCOL 必须为 http2、quic 或 auto。")

    sb_version = str(st.secrets.get("SINGBOX_VERSION", "1.14.2")).strip()
    cf_version = str(st.secrets.get("CLOUDFLARED_VERSION", "latest")).strip()

    if not re.fullmatch(r"\d+\.\d+\.\d+", sb_version):
        raise ValueError("SINGBOX_VERSION 必须为版本号，例如 1.14.2。")

    if (
        cf_version != "latest"
        and not re.fullmatch(r"\d+\.\d+\.\d+", cf_version)
    ):
        raise ValueError("CLOUDFLARED_VERSION 必须为 latest 或版本号。")

    return {
        "secret": secret,
        "token": token,
        "uuid": uid,
        "domain": domain,
        "port": port,
        "metrics_port": metrics_port,
        "protocol": protocol,
        "sb_version": sb_version,
        "cf_version": cf_version,
    }


# ============================================================
# 下载与安装
# ============================================================

def get_bytes(url, timeout=30):
    request = Request(
        url,
        headers={
            "User-Agent": "agsb-manager",
            "Accept": "application/json",
        },
    )
    with urlopen(request, timeout=timeout) as response:
        return response.read()


def install_binary(repo, tag, asset_name, target, archive=False):
    """
    从官方 GitHub Release 下载。
    如 Release 提供 SHA256 digest，则验证。
    不执行 tar.extractall。
    """
    if target.exists():
        return

    endpoint = "latest" if tag == "latest" else f"tags/{tag}"
    api_url = f"https://api.github.com/repos/{repo}/releases/{endpoint}"

    try:
        release = json.loads(get_bytes(api_url))
    except Exception as exc:
        raise RuntimeError(
            f"无法读取 {repo} 的 Release {tag}：{exc}"
        ) from exc

    asset = next(
        (
            item
            for item in release.get("assets", [])
            if item.get("name") == asset_name
        ),
        None,
    )

    if asset is None:
        raise RuntimeError(
            f"Release {tag} 中找不到 {asset_name}，"
            "请检查版本号与架构。"
        )

    fd, filename = tempfile.mkstemp(dir=ROOT, prefix=".download-")
    temporary = Path(filename)
    binary_temporary = Path(str(target) + ".tmp")

    try:
        request = Request(
            asset["browser_download_url"],
            headers={"User-Agent": "agsb-manager"},
        )

        digest = hashlib.sha256()

        with os.fdopen(fd, "wb") as output:
            with urlopen(request, timeout=60) as response:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    output.write(chunk)

        expected = asset.get("digest") or ""

        if expected.startswith("sha256:"):
            if not hmac.compare_digest(digest.hexdigest(), expected[7:]):
                raise RuntimeError("下载文件 SHA256 校验失败。")
        else:
            log_event(
                f"{asset_name} 未提供 SHA256 digest，仅通过 HTTPS 下载。"
            )

        if archive:
            with tarfile.open(temporary, "r:gz") as tar:
                members = [
                    member
                    for member in tar.getmembers()
                    if member.isfile()
                    and Path(member.name).name == "sing-box"
                ]

                if len(members) != 1:
                    raise RuntimeError("压缩包内 sing-box 文件数量异常。")

                source = tar.extractfile(members[0])
                if source is None:
                    raise RuntimeError("无法读取压缩包内 sing-box。")

                with source, binary_temporary.open("wb") as output:
                    shutil.copyfileobj(source, output)

            os.chmod(binary_temporary, 0o700)
            os.replace(binary_temporary, target)

        else:
            os.chmod(temporary, 0o700)
            os.replace(temporary, target)

        log_event(f"已安装 {asset_name}")

    finally:
        temporary.unlink(missing_ok=True)
        binary_temporary.unlink(missing_ok=True)


def get_binaries(cfg):
    machine = platform.machine().lower()

    arch = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(machine)

    if arch is None:
        raise ValueError(f"不支持的架构：{machine}")

    sb_path = ROOT / f"sing-box-{cfg['sb_version']}-{arch}"
    cf_path = ROOT / f"cloudflared-{cfg['cf_version']}-{arch}"

    install_binary(
        repo="SagerNet/sing-box",
        tag=f"v{cfg['sb_version']}",
        asset_name=f"sing-box-{cfg['sb_version']}-linux-{arch}.tar.gz",
        target=sb_path,
        archive=True,
    )

    install_binary(
        repo="cloudflare/cloudflared",
        tag=cfg["cf_version"],
        asset_name=f"cloudflared-linux-{arch}",
        target=cf_path,
    )

    return sb_path, cf_path


# ============================================================
# 进程管理
# ============================================================

def pid_file(name):
    return ROOT / f"{name}.pid.json"


def get_process(name):
    """验证 PID、创建时间和程序路径，避免误认其他进程。"""
    record = read_json(pid_file(name), {})

    try:
        process = psutil.Process(record["pid"])

        if abs(process.create_time() - record["created"]) > 0.01:
            return None

        if (
            not process.is_running()
            or process.status() == psutil.STATUS_ZOMBIE
        ):
            return None

        if Path(process.exe()).resolve() != Path(record["exe"]).resolve():
            return None

        return process

    except (KeyError, TypeError, psutil.Error, OSError):
        return None


def stop_process(name):
    """只停止本程序登记并验证过的进程。"""
    process = get_process(name)

    if process is not None:
        try:
            process.terminate()
            try:
                process.wait(timeout=8)
            except psutil.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

            log_event(f"已停止 {name}")

        except psutil.NoSuchProcess:
            pass

    pid_file(name).unlink(missing_ok=True)


def launch_process(name, command, config_fingerprint, env=None):
    log_path = ROOT / f"{name}.log"

    if log_path.exists() and log_path.stat().st_size > 5 * 1024 * 1024:
        os.replace(log_path, ROOT / f"{name}.log.1")

    with log_path.open("a", encoding="utf-8") as output:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        output.write(f"\n{timestamp} 启动进程\n")
        output.flush()

        child = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )

    try:
        process = psutil.Process(child.pid)

        record = {
            "pid": child.pid,
            "created": process.create_time(),
            "exe": str(Path(command[0]).resolve()),
            "fingerprint": config_fingerprint,
        }

        atomic_text(pid_file(name), json.dumps(record))

        time.sleep(0.3)

        if child.poll() is not None:
            raise RuntimeError(
                f"{name} 启动即退出，请查看对应日志。"
            )

    except Exception:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()

        pid_file(name).unlink(missing_ok=True)
        raise

    log_event(f"已启动 {name} PID={child.pid}")


# ============================================================
# 探测
# ============================================================

def websocket_probe(port, domain):
    """
    检查本地 WebSocket 握手。
    探测结束会关闭连接，可能产生连接关闭日志。
    不代表 VLESS 鉴权或完整代理链路成功。
    """
    key = base64.b64encode(os.urandom(16)).decode()

    request = (
        "GET / HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )

    try:
        with socket.create_connection(
            ("127.0.0.1", port),
            timeout=2,
        ) as connection:
            connection.sendall(request.encode("ascii"))

            data = b""
            while b"\r\n\r\n" not in data and len(data) < 16384:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                data += chunk

        header = data.decode("iso-8859-1")
        first_line = header.split("\r\n", 1)[0]

        fields = {}
        for line in header.split("\r\n")[1:\]:
            if not line:
                break
            if ":" in line:
                name, value = line.split(":", 1)
                fields[name.strip().lower()] = value.strip()

        expected_accept = base64.b64encode(
            hashlib.sha1(
                (
                    key
                    + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                ).encode("ascii")
            ).digest()
        ).decode()

        parts = first_line.split()
        valid_status = len(parts) >= 2 and parts[1] == "101"

        valid_accept = hmac.compare_digest(
            fields.get("sec-websocket-accept", ""),
            expected_accept,
        )

        valid_upgrade = (
            fields.get("upgrade", "").lower() == "websocket"
        )

        return (
            valid_status and valid_accept and valid_upgrade,
            first_line or "无响应",
        )

    except OSError as exc:
        return False, str(exc)


def get_tunnel_connections(cfg):
    try:
        url = (
            f"http://127.0.0.1:{cfg['metrics_port']}/metrics"
        )

        text = get_bytes(url, timeout=2).decode()

        values = re.findall(
            r"^cloudflared_tunnel_ha_connections"
            r"(?:\{[^\n]*\})?\s+([0-9.eE+-]+)$",
            text,
            re.M,
        )

        if not values:
            return None

        return sum(float(value) for value in values)

    except Exception:
        return None


def fingerprint(data):
    return hashlib.sha256(
        json.dumps(data, sort_keys=True).encode()
    ).hexdigest()


# ============================================================
# 服务恢复
# ============================================================

def ensure_services(cfg, force=None, manual=False):
    """
    必须在 LOCK 内调用。

    force:
        None   按需恢复
        sb     重启 sing-box
        argo   重启隧道
        all    重启全部

    不因一次探测失败重启存活进程。
    """
    if PAUSED_FILE.exists() and not manual:
        return

    attempts = read_json(ATTEMPTS_FILE, {})
    now = time.time()

    if (
        not manual
        and now - attempts.get("last", 0)
        < attempts.get("delay", 0)
    ):
        return

    sb_config = {
        "log": {
            "level": "info",
            "timestamp": True,
        },
        "inbounds": [
            {
                "type": "vless",
                "tag": "vless-in",
                "listen": "127.0.0.1",
                "listen_port": cfg["port"],
                "users": [{"uuid": cfg["uuid"]}],
                "transport": {
                    "type": "ws",
                    "path": "/",
                },
            }
        ],
        "outbounds": [
            {
                "type": "direct",
                "tag": "direct",
            }
        ],
    }

    sb_fp = fingerprint([sb_config, cfg["sb_version"]])

    cf_fp = fingerprint([
        cfg["token"],
        cfg["protocol"],
        cfg["metrics_port"],
        cfg["cf_version"],
    ])

    needed = {}

    for name, expected in (("sb", sb_fp), ("argo", cf_fp)):
        record = read_json(pid_file(name), {})

        needed[name] = (
            get_process(name) is None
            or record.get("fingerprint") != expected
            or force in (name, "all")
        )

    if not any(needed.values()):
        return

    try:
        sb_path, cf_path = get_binaries(cfg)

        if needed["sb"]:

            candidate = ROOT / "sb.candidate.json"

            atomic_text(
                candidate,
                json.dumps(sb_config, indent=2),
            )

            checked = subprocess.run(
                [
                    str(sb_path),
                    "check",
                    "-c",
                    str(candidate),
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if checked.returncode != 0:
                details = (checked.stderr or checked.stdout)[-2000:]
                raise RuntimeError(
                    f"sing-box 配置校验失败：\n{details}"
                )

            stop_process("sb")
            os.replace(candidate, SB_CONFIG_FILE)

            launch_process(
                "sb",
                [
                    str(sb_path),
                    "run",
                    "-c",
                    str(SB_CONFIG_FILE),
                ],
                sb_fp,
            )

            ready = False

            for _ in range(15):
                ready, _ = websocket_probe(
                    cfg["port"],
                    cfg["domain"],
                )

                if ready or get_process("sb") is None:
                    break

                time.sleep(0.2)

            if not ready:
                stop_process("sb")
                raise RuntimeError(
                    "本地 WebSocket 握手失败，"
                    "已停止本次启动的 sing-box，请查看日志。"
                )

        if needed["argo"]:

            stop_process("argo")

            env = os.environ.copy()
            env["TUNNEL_TOKEN"] = cfg["token"]

            launch_process(
                "argo",
                [
                    str(cf_path),
                    "tunnel",
                    "--no-autoupdate",
                    "--protocol",
                    cfg["protocol"],
                    "--metrics",
                    f"127.0.0.1:{cfg['metrics_port']}",
                    "--loglevel",
                    "info",
                    "run",
                ],
                cf_fp,
                env=env,
            )

        atomic_text(
            ATTEMPTS_FILE,
            json.dumps({
                "last": time.time(),
                "delay": 10,
            }),
        )

        ERROR_FILE.unlink(missing_ok=True)

    except Exception as exc:
        delay = min(
            300,
            max(15, attempts.get("delay", 0) * 2),
        )

        atomic_text(
            ATTEMPTS_FILE,
            json.dumps({
                "last": time.time(),
                "delay": delay,
            }),
        )

        message = redact(str(exc), cfg)
        atomic_text(ERROR_FILE, message)
        log_event(f"启动失败：{message}")
        raise


# ============================================================
# 节点
# ============================================================

def generate_node(cfg):
    query = urlencode({
        "type": "ws",
        "encryption": "none",
        "security": "tls",
        "sni": cfg["domain"],
        "host": cfg["domain"],
        "path": "/",
    })

    return (
        f"vless://{cfg['uuid']}@{cfg['domain']}:443"
        f"?{query}#{quote('VLWS-TLS-Direct')}"
    )


# ============================================================
# 登录
# ============================================================

def render_login(cfg):
    # 管理口令变化后，使已有会话重新登录。
    secret_fingerprint = hashlib.sha256(
        cfg["secret"].encode()
    ).hexdigest()

    if (
        st.session_state.get("authenticated")
        and st.session_state.get("auth_fingerprint")
        == secret_fingerprint
    ):
        return True

    st.session_state.authenticated = False
    st.title("服务管理登录")

    with st.form("login"):
        password = st.text_input(
            "管理口令",
            type="password",
        )
        submitted = st.form_submit_button("登录")

    if submitted:
        now = time.time()

        if now < st.session_state.get("login_after", 0):
            st.error("尝试过于频繁，请稍后重新登录。")

        elif hmac.compare_digest(
            password.encode(),
            cfg["secret"].encode(),
        ):
            st.session_state.authenticated = True
            st.session_state.auth_fingerprint = secret_fingerprint
            st.rerun()

        else:
            st.session_state.login_after = now + 3
            st.error("口令错误。")

    st.caption(
        "简单口令不替代正式身份认证；"
        "请仅向可信用户开放管理面板。"
    )

    return False


# ============================================================
# 状态与日志面板
# ============================================================

@st.fragment(run_every="15s")
def render_status(cfg):
    if not PAUSED_FILE.exists():
        try:
            with LOCK:
                ensure_services(cfg)

        except Timeout:
            st.info("其他会话正在操作服务，本次跳过恢复。")

        except Exception as exc:
            st.error(redact(str(exc), cfg))

    sb_alive = get_process("sb") is not None
    cf_alive = get_process("argo") is not None

    if sb_alive:
        ws_ok, ws_message = websocket_probe(
            cfg["port"],
            cfg["domain"],
        )
    else:
        ws_ok, ws_message = False, "进程未运行"

    connections = (
        get_tunnel_connections(cfg)
        if cf_alive
        else None
    )

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "sing-box 进程",
        "运行" if sb_alive else "停止",
    )

    c2.metric(
        "本地 WS 握手",
        "成功" if ws_ok else "失败",
    )

    c3.metric(
        "隧道活动连接",
        "未知" if connections is None else str(int(connections)),
    )

    cf_status = "运行" if cf_alive else "停止"

    st.caption(
        f"cloudflared：{cf_status}；"
        f"本地探测：{ws_message}"
    )

    if PAUSED_FILE.exists():
        st.warning("服务已暂停，自动恢复关闭。")

    elif ws_ok and connections is not None and connections > 0:
        st.success(
            "本地握手成功，隧道存在活动连接。"
            "尚未验证客户端完整代理链路。"
        )

    else:
        st.warning(
            "服务尚未就绪或状态异常，请查看日志。"
            "不会因一次探测失败重启存活进程。"
        )

    if ERROR_FILE.exists():
        st.error(
            redact(
                ERROR_FILE.read_text(encoding="utf-8"),
                cfg,
            )
        )

    with st.expander("最近日志", expanded=False):
        st.caption(
            "本地握手探测会主动关闭连接，"
            "因此少量连接关闭日志不一定代表故障。"
        )

        for name in ("sb", "argo", "manager"):
            st.text(name)
            st.code(
                redact(
                    tail_log(ROOT / f"{name}.log"),
                    cfg,
                ),
                language="text",
            )


# ============================================================
# 主程序
# ============================================================

def main():
    st.set_page_config(
        page_title="隧道服务管理",
        layout="wide",
    )

    try:
        cfg = load_config()
    except Exception as exc:
        st.error(f"配置读取失败：{exc}")
        st.stop()

    if not render_login(cfg):
        return

    st.title("隧道服务管理")
    st.caption(
        "固定 UUID / 固定端口 / 独立进程恢复 / Direct 节点"
    )

    if st.sidebar.button("退出登录"):
        st.session_state.authenticated = False
        st.session_state.pop("auth_fingerprint", None)
        st.rerun()

    st.info(
        "Cloudflare 对应域名的源站必须设置为："
        f"http://127.0.0.1:{cfg['port']}。"
        "本程序不会自动修改控制台路由。"
    )

    actions = {
        "启动 / 恢复": None,
        "仅重启 sing-box": "sb",
        "仅重启隧道": "argo",
        "重启全部": "all",
        "暂停服务": "stop",
    }

    selected = st.selectbox("选择操作", list(actions))

    if st.button("执行操作", type="primary"):
        try:
            with LOCK:
                action = actions[selected]

                if action == "stop":
                    atomic_text(PAUSED_FILE, "paused")
                    stop_process("argo")
                    stop_process("sb")

                else:
                    PAUSED_FILE.unlink(missing_ok=True)

                    with st.spinner("检查配置并执行操作..."):
                        ensure_services(
                            cfg,
                            force=action,
                            manual=True,
                        )

            st.success("操作完成，实际连接状态见下方。")

        except Timeout:
            st.warning("已有操作正在执行，本次未执行。")

        except Exception as exc:
            st.error(redact(str(exc), cfg))

    render_status(cfg)

    st.subheader("Direct 节点")

    st.caption(
        "链接含访问凭据，请勿公开。"
        "显示链接不代表服务当前可用。"
    )

    node = generate_node(cfg)

    st.code(node, language="text")

    st.download_button(
        "下载节点链接",
        data=node + "\n",
        file_name="nodes.txt",
        mime="text/plain",
    )

    st.caption(
        "自动检查仅在已登录页面会话活动时执行。"
        "不保证平台休眠期间服务继续运行。"
    )


if __name__ == "__main__":
    main()
