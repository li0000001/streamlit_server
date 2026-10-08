#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Linux / Streamlit 命名隧道管理面板。

依赖：
    streamlit>=1.37,<2
    psutil>=5.9,<8
    filelock>=3.13,<4

必须配置：
    SECRET_KEY
    UUID_STR
    ARGO_TOKEN
    CUSTOM_DOMAIN

默认本地端口：
    55555

Cloudflare 对应域名的源站必须手动配置为：
    http://127.0.0.1:55555

注意：
    1. 不会自动修改 Cloudflare 控制台路由。
    2. 不会随机生成 UUID 或监听端口。
    3. 自动恢复仅在已登录页面会话活动时执行。
    4. 不是独立常驻守护服务，不保证平台休眠期间运行。
    5. 本地握手和隧道连接正常，不等于完整代理链路正常。
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
from urllib.parse import urlencode, quote
from urllib.request import Request, urlopen

import psutil
import streamlit as st

from filelock import FileLock, Timeout


# ============================================================
# 全局路径
# ============================================================

ROOT = Path.home() / ".agsb"
ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)

LOCK = FileLock(str(ROOT / "manager.lock"), timeout=1)

PAUSED = ROOT / "paused"
SB_CONFIG = ROOT / "sb.json"


# ============================================================
# 文件与日志辅助函数
# ============================================================

def atomic_text(path, text):
    """原子写入文本，避免并发读到半写入文件。"""
    fd, name = tempfile.mkstemp(
        dir=ROOT,
        prefix=".tmp-",
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)

        os.chmod(name, 0o600)
        os.replace(name, path)

    finally:
        Path(name).unlink(missing_ok=True)


def read_json(path, default=None):
    """读取 JSON，失败时返回默认值。"""
    try:
        return json.loads(
            path.read_text(encoding="utf-8")
        )

    except (OSError, ValueError):
        return default


def log_event(text):
    """记录管理操作，不写入 Token 等明文凭据。"""
    with (ROOT / "manager.log").open(
        "a",
        encoding="utf-8",
    ) as f:
        f.write(
            time.strftime("%Y-%m-%d %H:%M:%S ")
            + text
            + "\n"
        )


def tail(path, count=100):
    """读取日志最后若干行。"""
    try:
        with path.open(
            encoding="utf-8",
            errors="replace",
        ) as f:
            return "".join(
                deque(f, maxlen=count)
            )

    except OSError:
        return "暂无日志"


def redact(text, cfg):
    """在面板显示日志前隐藏已知凭据。"""
    for key in ("token", "secret", "uuid"):
        text = text.replace(
            cfg[key],
            "[已隐藏]",
        )

    return re.sub(
        r"vless://[^\s]+",
        "[节点链接已隐藏]",
        text,
    )


# ============================================================
# 配置读取与校验
# ============================================================

def load_config():
    """读取 Streamlit Secrets 并校验。"""
    if platform.system() != "Linux":
        raise ValueError(
            "此版本仅支持 Linux 部署环境。"
        )

    secret = str(
        st.secrets.get("SECRET_KEY", "")
    ).strip()

    token = str(
        st.secrets.get("ARGO_TOKEN", "")
    ).strip()

    uid = str(
        st.secrets.get("UUID_STR", "")
    ).strip()

    domain = str(
        st.secrets.get("CUSTOM_DOMAIN", "")
    ).strip().lower()

    if not all((secret, token, uid, domain)):
        raise ValueError(
            "请设置 SECRET_KEY、ARGO_TOKEN、"
            "UUID_STR、CUSTOM_DOMAIN；"
            "不再随机生成 UUID。"
        )

    # 校验并标准化 UUID。
    uid = str(uuid.UUID(uid))

    if len(secret) < 16:
        raise ValueError(
            "SECRET_KEY 至少需要 16 个字符。"
        )

    if (
        not re.fullmatch(
            r"?:[a-z0-9.-]*[a-z0-9]?",
            domain,
        )
        or "." not in domain
    ):
        raise ValueError(
            "CUSTOM_DOMAIN 只填写域名，"
            "不带协议、端口或路径。"
        )

    port = int(
        st.secrets.get("PORT_VM_WS", 55555)
    )

    metrics = int(
        st.secrets.get("METRICS_PORT", 55556)
    )

    if (
        not (
            1024 <= port <= 65535
            and 1024 <= metrics <= 65535
        )
        or port == metrics
    ):
        raise ValueError(
            "服务端口和监控端口必须不同，"
            "范围为 1024 至 65535。"
        )

    protocol = str(
        st.secrets.get(
            "TUNNEL_PROTOCOL",
            "http2",
        )
    )

    if protocol not in ("http2", "quic", "auto"):
        raise ValueError(
            "TUNNEL_PROTOCOL 必须为 "
            "http2、quic 或 auto。"
        )

    # 沿用原脚本版本号。
    # 如果官方没有对应 Release，安装阶段会明确报错。
    version = str(
        st.secrets.get(
            "SINGBOX_VERSION",
            "1.14.2",
        )
    )

    cf_version = str(
        st.secrets.get(
            "CLOUDFLARED_VERSION",
            "latest",
        )
    )

    if not re.fullmatch(
        r"\d+\.\d+\.\d+",
        version,
    ):
        raise ValueError(
            "SINGBOX_VERSION 必须是稳定版本号。"
        )

    if (
        cf_version != "latest"
        and not re.fullmatch(
            r"\d+\.\d+\.\d+",
            cf_version,
        )
    ):
        raise ValueError(
            "CLOUDFLARED_VERSION 必须为 "
            "latest 或版本号。"
        )

    return {
        "secret": secret,
        "token": token,
        "uuid": uid,
        "domain": domain,
        "port": port,
        "metrics": metrics,
        "protocol": protocol,
        "sb_version": version,
        "cf_version": cf_version,
    }


# ============================================================
# 官方 Release 下载与安装
# ============================================================

def get_bytes(url, timeout=30):
    req = Request(
        url,
        headers={
            "User-Agent": "agsb-manager",
            "Accept": "application/json",
        },
    )

    with urlopen(req, timeout=timeout) as response:
        return response.read()


def install_binary(
    repo,
    tag,
    asset_name,
    target,
    archive=False,
):
    """
    从官方 GitHub Release 下载。

    如果 Release 提供 SHA256 digest，则验证。
    压缩包只读取一个普通文件，不执行 extractall。
    已存在的二进制不会每次启动重复下载。
    """
    if target.exists():
        return

    endpoint = (
        "latest"
        if tag == "latest"
        else "tags/" + tag
    )

    api_url = (
        f"https://api.github.com/repos/{repo}"
        f"/releases/{endpoint}"
    )

    release = json.loads(
        get_bytes(api_url)
    )

    asset = next(
        (
            item
            for item in release["assets"]
            if item["name"] == asset_name
        ),
        None,
    )

    if not asset:
        raise RuntimeError(
            f"官方 Release 中没有 {asset_name}"
        )

    fd, temp_name = tempfile.mkstemp(
        dir=ROOT,
        prefix=".download-",
    )

    temp = Path(temp_name)

    try:
        req = Request(
            asset["browser_download_url"],
            headers={
                "User-Agent": "agsb-manager",
            },
        )

        digest = hashlib.sha256()

        with (
            os.fdopen(fd, "wb") as out,
            urlopen(req, timeout=60) as response,
        ):
            while True:
                chunk = response.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                digest.update(chunk)
                out.write(chunk)

        expected = asset.get("digest") or ""

        if expected.startswith("sha256:"):
            if not hmac.compare_digest(
                digest.hexdigest(),
                expected[7:],
            ):
                raise RuntimeError(
                    "下载文件 SHA256 校验失败。"
                )

        else:
            log_event(
                f"{asset_name} 未提供 SHA256 digest，"
                "仅通过 HTTPS 下载。"
            )

        if archive:
            with tarfile.open(
                temp,
                "r:gz",
            ) as tar:
                members = [
                    member
                    for member in tar.getmembers()
                    if (
                        member.isfile()
                        and Path(member.name).name
                        == "sing-box"
                    )
                ]

                if len(members) != 1:
                    raise RuntimeError(
                        "压缩包内核心文件数量异常。"
                    )

                with (
                    tar.extractfile(members[0]) as src,
                    target.with_suffix(".tmp").open(
                        "wb"
                    ) as out,
                ):
                    shutil.copyfileobj(
                        src,
                        out,
                    )

            os.chmod(
                target.with_suffix(".tmp"),
                0o700,
            )

            os.replace(
                target.with_suffix(".tmp"),
                target,
            )

        else:
            os.chmod(temp, 0o700)
            os.replace(temp, target)

        log_event(
            f"已安装 {asset_name}"
        )

    finally:
        temp.unlink(missing_ok=True)

        target.with_suffix(".tmp").unlink(
            missing_ok=True
        )


def binaries(cfg):
    """按架构安装并返回两个二进制路径。"""
    machine = platform.machine().lower()

    arch = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(machine)

    if not arch:
        raise ValueError(
            f"不支持的架构：{machine}"
        )

    sb = ROOT / (
        f"sing-box-{cfg['sb_version']}-{arch}"
    )

    cf = ROOT / (
        f"cloudflared-{cfg['cf_version']}-{arch}"
    )

    install_binary(
        repo="SagerNet/sing-box",
        tag="v" + cfg["sb_version"],
        asset_name=(
            f"sing-box-{cfg['sb_version']}"
            f"-linux-{arch}.tar.gz"
        ),
        target=sb,
        archive=True,
    )

    install_binary(
        repo="cloudflare/cloudflared",
        tag=cfg["cf_version"],
        asset_name=(
            f"cloudflared-linux-{arch}"
        ),
        target=cf,
    )

    return sb, cf


# ============================================================
# 进程管理
# ============================================================

def process(name):
    """
    获取本程序登记的进程。

    同时验证：
        PID
        进程创建时间
        可执行文件路径

    避免仅凭旧 PID 文件误杀其他进程。
    """
    record = read_json(
        ROOT / f"{name}.pid.json",
        {},
    )

    try:
        p = psutil.Process(
            record["pid"]
        )

        if abs(
            p.create_time()
            - record["created"]
        ) > 0.01:
            return None

        if (
            p.status() == psutil.STATUS_ZOMBIE
            or not p.is_running()
        ):
            return None

        if (
            Path(p.exe()).resolve()
            != Path(record["exe"]).resolve()
        ):
            return None

        return p

    except (
        KeyError,
        psutil.Error,
        OSError,
    ):
        return None


def stop_one(name):
    """仅停止本程序登记并验证过的单个进程。"""
    p = process(name)

    if p:
        try:
            p.terminate()

            try:
                p.wait(timeout=8)

            except psutil.TimeoutExpired:
                p.kill()
                p.wait(timeout=3)

            log_event(
                f"已停止 {name}"
            )

        except psutil.NoSuchProcess:
            pass

    (
        ROOT / f"{name}.pid.json"
    ).unlink(missing_ok=True)


def launch(
    name,
    command,
    fingerprint,
    env=None,
):
    """启动进程并记录身份信息。"""
    path = ROOT / f"{name}.log"

    # 只在启动前轮换日志，
    # 不截断正在使用的日志文件。
    if (
        path.exists()
        and path.stat().st_size
        > 5 * 1024 * 1024
    ):
        os.replace(
            path,
            ROOT / f"{name}.log.1",
        )

    with path.open(
        "a",
        encoding="utf-8",
    ) as f:
        f.write(
            "\n"
            + time.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            + " 启动进程\n"
        )

        f.flush()

        child = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=f,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )

    try:
        p = psutil.Process(child.pid)

        record = {
            "pid": child.pid,
            "created": p.create_time(),
            "exe": str(
                Path(command[0]).resolve()
            ),
            "fingerprint": fingerprint,
        }

        atomic_text(
            ROOT / f"{name}.pid.json",
            json.dumps(record),
        )

        time.sleep(0.3)

        if child.poll() is not None:
            raise RuntimeError(
                f"{name} 启动即退出，"
                "请查看对应日志。"
            )

    except Exception:
        if child.poll() is None:
            child.terminate()

            try:
                child.wait(timeout=3)

            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()

        raise

    log_event(
        f"已启动 {name} PID={child.pid}"
    )


# ============================================================
# 状态探测
# ============================================================

def websocket_probe(
    host,
    port,
    domain,
):
    """
    检查本地 WebSocket 握手。

    不代表：
        VLESS 鉴权成功
        客户端到 Cloudflare 正常
        完整代理链路正常

    探测结束会关闭连接，
    对应服务日志可能出现连接关闭提示。
    """
    key = base64.b64encode(
        os.urandom(16)
    ).decode()

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
            (host, port),
            timeout=2,
        ) as sock:
            sock.sendall(
                request.encode("ascii")
            )

            data = b""

            while (
                b"\r\n\r\n" not in data
                and len(data) < 16384
            ):
                chunk = sock.recv(4096)

                if not chunk:
                    break

                data += chunk

        line = (
            data.split(b"\r\n", 1)[0]
            .decode(errors="replace")
        )

        return (
            " 101 " in line,
            line or "无响应",
        )

    except OSError as e:
        return False, str(e)


def tunnel_connections(cfg):
    """
    读取 cloudflared 本地监控指标。

    指标不可读取或名称不匹配时返回 None，
    不将未知状态当成零连接。
    """
    try:
        url = (
            f"http://127.0.0.1:"
            f"{cfg['metrics']}/metrics"
        )

        text = get_bytes(
            url,
            timeout=2,
        ).decode()

        values = re.findall(
            r"^cloudflared_tunnel_ha_connections"
            r"(?:\{[^\n]*\})?"
            r"\s+([0-9.eE+-]+)$",
            text,
            re.M,
        )

        if not values:
            return None

        return sum(
            float(value)
            for value in values
        )

    except Exception:
        return None


def fingerprint(data):
    """计算配置指纹，不保存 Token 明文。"""
    return hashlib.sha256(
        json.dumps(
            data,
            sort_keys=True,
        ).encode()
    ).hexdigest()


# ============================================================
# 服务启动与恢复
# ============================================================

def ensure_services(
    cfg,
    force=None,
    manual=False,
):
    """
    必须在 LOCK 内调用。

    force:
        None   按需启动或恢复
        "sb"   重启 sing-box
        "argo" 重启 cloudflared
        "all"  重启全部

    自动恢复只针对进程退出或配置变化。
    不因单次握手失败或指标异常重启存活进程。
    """
    if PAUSED.exists() and not manual:
        return

    state_path = ROOT / "attempts.json"

    attempts = read_json(
        state_path,
        {},
    )

    now = time.time()

    # 自动恢复退避，避免持续失败时反复重启。
    if (
        not manual
        and now - attempts.get("last", 0)
        < attempts.get("delay", 0)
    ):
        return

    sb_data = {
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
                "users": [
                    {
                        "uuid": cfg["uuid"],
                    }
                ],
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

    sb_fp = fingerprint(
        [
            sb_data,
            cfg["sb_version"],
        ]
    )

    cf_fp = fingerprint(
        [
            cfg["token"],
            cfg["protocol"],
            cfg["metrics"],
            cfg["cf_version"],
        ]
    )

    need = {}

    for name, fp in (
        ("sb", sb_fp),
        ("argo", cf_fp),
    ):
        record = read_json(
            ROOT / f"{name}.pid.json",
            {},
        )

        need[name] = (
            process(name) is None
            or record.get("fingerprint") != fp
            or force in (name, "all")
        )

    if not any(need.values()):
        return

    try:
        sb, cf = binaries(cfg)

        if need["sb"]:
            # 先验证新配置，再停止旧进程。
            candidate = (
                ROOT / "sb.candidate.json"
            )

            atomic_text(
                candidate,
                json.dumps(
                    sb_data,
                    indent=2,
                ),
            )

            checked = subprocess.run(
                [
                    str(sb),
                    "check",
                    "-c",
                    str(candidate),
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if checked.returncode:
                raise RuntimeError(
                    "sing-box 配置校验失败："
                    + checked.stderr[-2000:]
                )

            stop_one("sb")

            os.replace(
                candidate,
                SB_CONFIG,
            )

            launch(
                name="sb",
                command=[
                    str(sb),
                    "run",
                    "-c",
                    str(SB_CONFIG),
                ],
                fingerprint=sb_fp,
            )

            ok = False

            for _ in range(15):
                ok, _ = websocket_probe(
                    "127.0.0.1",
                    cfg["port"],
                    cfg["domain"],
                )

                if ok:
                    break

                if process("sb") is None:
                    break

                time.sleep(0.2)

            if not ok:
                stop_one("sb")

                raise RuntimeError(
                    "本地 WebSocket 握手未成功，"
                    "已停止本次启动的 sing-box，"
                    "请查看日志。"
                )

        if need["argo"]:
            stop_one("argo")

            env = os.environ.copy()

            # Token 通过环境变量传入，
            # 不放入启动命令参数。
            env["TUNNEL_TOKEN"] = cfg["token"]

            launch(
                name="argo",
                command=[
                    str(cf),
                    "tunnel",
                    "--no-autoupdate",
                    "--protocol",
                    cfg["protocol"],
                    "--metrics",
                    (
                        f"127.0.0.1:"
                        f"{cfg['metrics']}"
                    ),
                    "--loglevel",
                    "info",
                    "run",
                ],
                fingerprint=cf_fp,
                env=env,
            )

        atomic_text(
            state_path,
            json.dumps(
                {
                    "last": now,
                    "delay": 10,
                }
            ),
        )

        (
            ROOT / "last_error.txt"
        ).unlink(missing_ok=True)

    except Exception as e:
        delay = min(
            300,
            max(
                15,
                attempts.get("delay", 0) * 2,
            ),
        )

        atomic_text(
            state_path,
            json.dumps(
                {
                    "last": now,
                    "delay": delay,
                }
            ),
        )

        message = redact(
            str(e),
            cfg,
        )

        atomic_text(
            ROOT / "last_error.txt",
            message,
        )

        log_event(
            "启动失败：" + message
        )

        raise


# ============================================================
# 节点链接
# ============================================================

def node_link(cfg):
    """只生成 Direct 域名节点，减少排查变量。"""
    query = urlencode(
        {
            "type": "ws",
            "encryption": "none",
            "security": "tls",
            "sni": cfg["domain"],
            "host": cfg["domain"],
            "path": "/",
        }
    )

    name = quote(
        "VLWS-TLS-Direct"
    )

    return (
        f"vless://{cfg['uuid']}"
        f"@{cfg['domain']}:443"
        f"?{query}"
        f"#{name}"
    )


# ============================================================
# 登录界面
# ============================================================

def login(cfg):
    if st.session_state.get(
        "authenticated"
    ):
        return True

    st.title("服务管理登录")

    with st.form("login"):
        password = st.text_input(
            "管理口令",
            type="password",
        )

        submitted = st.form_submit_button(
            "登录"
        )

    if submitted:
        now = time.time()

        if now < st.session_state.get(
            "login_after",
            0,
        ):
            st.error(
                "尝试过于频繁，"
                "请稍后重新登录。"
            )

        elif hmac.compare_digest(
            password.encode(),
            cfg["secret"].encode(),
        ):
            st.session_state.authenticated = True
            st.rerun()

        else:
            st.session_state.login_after = (
                now + 3
            )

            st.error("口令错误。")

    st.caption(
        "这是简单管理口令，不替代正式身份认证；"
        "仅向可信用户开放面板。"
    )

    return False


# ============================================================
# 周期状态面板
# ============================================================

@st.fragment(run_every="15s")
def status_panel(cfg):
    """
    仅在页面会话活动时周期执行。

    自动恢复：
        进程退出
        配置发生变化

    不自动恢复：
        单次探测失败
        单次指标读取失败
        客户端测速失败
    """
    if not PAUSED.exists():
        try:
            with LOCK:
                ensure_services(cfg)

        except Timeout:
            st.info(
                "其他会话正在操作服务，"
                "本次跳过恢复。"
            )

        except Exception as e:
            st.error(
                redact(str(e), cfg)
            )

    sb_alive = (
        process("sb") is not None
    )

    cf_alive = (
        process("argo") is not None
    )

    if sb_alive:
        ws_ok, ws_message = websocket_probe(
            "127.0.0.1",
            cfg["port"],
            cfg["domain"],
        )

    else:
        ws_ok = False
        ws_message = "进程未运行"

    connections = (
        tunnel_connections(cfg)
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
        (
            "未知"
            if connections is None
            else str(int(connections))
        ),
    )

    cf_status = (
        "运行" if cf_alive else "停止"
    )

    st.caption(
        f"cloudflared 进程：{cf_status}；"
        f"本地探测：{ws_message}"
    )

    if PAUSED.exists():
        st.warning(
            "服务已暂停，自动恢复关闭。"
        )

    elif (
        ws_ok
        and connections is not None
        and connections > 0
    ):
        st.success(
            "本地握手成功，隧道存在活动连接；"
            "尚未验证客户端完整代理链路。"
        )

    else:
        st.warning(
            "服务尚未就绪或状态异常，"
            "请查看日志。"
            "不会因一次探测失败重启存活进程。"
        )

    error_path = (
        ROOT / "last_error.txt"
    )

    if error_path.exists():
        st.error(
            redact(
                error_path.read_text(
                    encoding="utf-8"
                ),
                cfg,
            )
        )

    with st.expander(
        "最近日志",
        expanded=False,
    ):
        for name in (
            "sb",
            "argo",
            "manager",
        ):
            st.text(name)

            st.code(
                redact(
                    tail(
                        ROOT / f"{name}.log"
                    ),
                    cfg,
                ),
                language="text",
            )


# ============================================================
# 主界面
# ============================================================

def main():
    st.set_page_config(
        page_title="隧道服务管理",
        layout="wide",
    )

    try:
        cfg = load_config()

    except Exception as e:
        st.error(
            f"配置读取失败：{e}"
        )

        st.stop()

    if not login(cfg):
        return

    st.title("隧道服务管理")

    st.caption(
        "固定 UUID / 固定端口 / "
        "独立进程恢复 / 命名隧道 / Direct 节点"
    )

    if st.sidebar.button("退出登录"):
        st.session_state.authenticated = False
        st.rerun()

    st.info(
        "Cloudflare 对应域名的源站应为 "
        f"http://127.0.0.1:{cfg['port']}；"
        "本程序不会修改控制台路由。"
    )

    options = {
        "启动 / 恢复": None,
        "仅重启 sing-box": "sb",
        "仅重启隧道": "argo",
        "重启全部": "all",
        "暂停服务": "stop",
    }

    action = st.selectbox(
        "操作",
        list(options),
    )

    if st.button(
        "执行操作",
        type="primary",
    ):
        try:
            with LOCK:
                if options[action] == "stop":
                    atomic_text(
                        PAUSED,
                        "paused",
                    )

                    stop_one("argo")
                    stop_one("sb")

                else:
                    PAUSED.unlink(
                        missing_ok=True
                    )

                    with st.spinner(
                        "检查配置并执行操作..."
                    ):
                        ensure_services(
                            cfg,
                            force=options[action],
                            manual=True,
                        )

            st.success(
                "操作完成；"
                "实际连接状态见下方。"
            )

        except Timeout:
            st.warning(
                "已有操作正在执行，"
                "本次未执行。"
            )

        except Exception as e:
            st.error(
                redact(str(e), cfg)
            )

    status_panel(cfg)

    st.subheader("Direct 节点")

    st.caption(
        "链接含访问凭据，请勿公开。"
        "暂停或异常时，链接仍可显示，"
        "但不代表服务可用。"
    )

    link = node_link(cfg)

    st.code(
        link,
        language="text",
    )

    st.download_button(
        "下载节点链接",
        link + "\n",
        file_name="nodes.txt",
        mime="text/plain",
    )

    st.caption(
        "自动检查仅在已登录页面会话活动时运行；"
        "不提供平台休眠期间的保活保证。"
    )


if __name__ == "__main__":
    main()
