"""一键式「蓝牙 STA 局域网唤醒 ➔ 明文 HTTP WebDAV 只读增量同步」编排器。

零业务宿主耦合，支持任何上层应用直接调用。Wi-Fi 密码仅在单次调用内存中用于构造蓝牙 CBOR 帧，
绝不写入日志、游标或磁盘配置文件。
"""

from __future__ import annotations

import json
import secrets
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import GlassesKitConfig
from .gcsp_protocol import (
    ChannelId,
    NameSpace,
    PayloadDataType,
    RequestType,
    build_command_frame_v1,
    cbor_loads,
    parse_frame_v1,
)
from .webfs_readonly_client import SyncCursorStore, WebFSReadOnlyClient


@dataclass
class StaWakeResult:
    """蓝牙 STA 唤醒眼镜联网后的解析回执。"""

    ok: bool
    ip: str = ""
    port: int = 0
    error_code: int = -1
    random_b: str = ""
    ssid: str = ""
    error_message: str = ""
    raw_events_count: int = 0


@dataclass
class StaSyncSummary:
    """端到端 STA + WebDAV 只读增量同步结果摘要。"""

    ok: bool
    mode: str = "ble_sta"
    wake_result: Optional[StaWakeResult] = None
    remote_dirs: List[str] = field(default_factory=list)
    downloaded: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    error_message: str = ""


def parse_sta_wake_events(jsonl_lines: List[str]) -> StaWakeResult:
    """从 glasses-ble-bridge JSONL 输出中解析 ns=6 cmd=0x02 的眼镜局域网 IP 与动态端口。"""
    events_count = 0
    for line in jsonl_lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        events_count += 1
        if evt.get("event") == "l2cap_rx" and evt.get("ns") == NameSpace.SET_WIFI and evt.get("cmd") == 2:
            raw_hex = evt.get("hex", "")
            if not raw_hex:
                continue
            try:
                frame = parse_frame_v1(bytes.fromhex(raw_hex), has_command_header=True)
                obj = cbor_loads(frame.payload)
                if isinstance(obj, dict):
                    err = int(obj.get("errorCode", -1))
                    ip = str(obj.get("IP", "") or "")
                    port = int(obj.get("port", 0) or 0)
                    random_b = str(obj.get("randomB", "") or "")
                    wifi_obj = obj.get("wifi") if isinstance(obj.get("wifi"), dict) else {}
                    ssid = str(wifi_obj.get("ssid", "") or "")
                    return StaWakeResult(
                        ok=(err == 0 and bool(ip) and port > 0),
                        ip=ip,
                        port=port,
                        error_code=err,
                        random_b=random_b,
                        ssid=ssid,
                        error_message="" if err == 0 else f"device returned errorCode={err}",
                        raw_events_count=events_count,
                    )
            except Exception as exc:
                return StaWakeResult(
                    ok=False,
                    error_message=f"解析 ns=6 cmd=0x02 回包失败: {exc}",
                    raw_events_count=events_count,
                )
    return StaWakeResult(
        ok=False,
        error_message="超时未收到眼镜 ns=6 cmd=0x02 局域网建联回执（请确认眼镜已开机且未占用连接）",
        raw_events_count=events_count,
    )


def wake_glasses_sta_lan(
    *,
    bridge_bin: Path,
    ssid: str,
    password: str,
    frequency_mhz: int = 5220,
    business_id: int = 3,
    wifi_type: int = 1,
    timeout_seconds: int = 25,
) -> StaWakeResult:
    """调用本地 CoreBluetooth 桥发送 ns=6 cmd=0x02 唤醒眼镜加入指定局域网 Wi-Fi。"""
    if not bridge_bin.exists():
        return StaWakeResult(ok=False, error_message=f"未找到蓝牙桥可执行文件: {bridge_bin}")
    if not ssid.strip():
        return StaWakeResult(ok=False, error_message="未提供局域网 Wi-Fi SSID")

    payload = {
        "ssid": ssid.strip(),
        "password": password,
        "frequency": int(frequency_mhz),
        "rssi": -50,
        "isEncrypted": 1 if password else 0,
        "businessID": int(business_id),
        "wifiType": int(wifi_type),
        "randomA": secrets.token_hex(16),
        "traceID": f"kit_sta_{secrets.token_hex(6)}",
    }
    frame_hex = build_command_frame_v1(
        NameSpace.SET_WIFI,
        0x02,
        payload,
        channel_id=ChannelId.MESSAGE,
        msg_id=0x40,
        req_type=RequestType.REQUEST,
        payload_type=PayloadDataType.CBOR_DATA,
    ).hex().upper()

    proc = subprocess.run(
        [str(bridge_bin), "--tx-hex", frame_hex, "--timeout", str(int(timeout_seconds))],
        capture_output=True,
        text=True,
        timeout=int(timeout_seconds) + 15,
        check=False,
    )
    lines = (proc.stdout or "").splitlines()
    result = parse_sta_wake_events(lines)
    if not result.ok and proc.returncode != 0 and not result.error_message:
        result.error_message = f"bridge exited with code {proc.returncode}"
    return result


def sync_via_ble_sta(
    config: GlassesKitConfig,
    *,
    ssid: Optional[str] = None,
    password: str = "",
    local_dir: Optional[Path] = None,
    cursor_path: Optional[Path] = None,
    max_dirs: Optional[int] = None,
) -> StaSyncSummary:
    """完整执行：蓝牙 STA 唤醒 ➔ 明文 WebDAV PROPFIND ➔ 只读增量同步到本地目录。"""
    target_ssid = (ssid or config.preferred_ssid or "").strip()
    bridge_path = Path(config.bridge_binary_path) if config.bridge_binary_path else Path("swift_bridge/glasses-ble-bridge")
    wake = wake_glasses_sta_lan(
        bridge_bin=bridge_path,
        ssid=target_ssid,
        password=password,
        frequency_mhz=config.sync_policy.sta_frequency_mhz,
        business_id=config.sync_policy.sta_business_id,
        wifi_type=config.sync_policy.sta_wifi_type,
        timeout_seconds=config.sync_policy.ble_timeout_seconds,
    )
    if not wake.ok:
        return StaSyncSummary(ok=False, wake_result=wake, error_message=wake.error_message)

    dest_dir = Path(local_dir or Path(config.storage_dir) / "webfs")
    c_path = Path(cursor_path or Path(config.storage_dir) / "webfs_cursor.json")
    cursor = SyncCursorStore(c_path)

    remote_root = config.sync_policy.webfs_root_path or "/DCIM/AliCamera"
    downloaded: List[str] = []
    skipped: List[str] = []
    remote_dirs: List[str] = []

    with WebFSReadOnlyClient(
        wake.ip,
        port=wake.port,
        proto="dav",
        root_path=remote_root,
    ) as client:
        entries = client.propfind(remote_root, depth="1")
        sub_dirs = [e.path for e in entries if e.is_dir and e.path.rstrip("/") != remote_root.rstrip("/")]
        remote_dirs = sub_dirs
        if max_dirs is not None and max_dirs > 0:
            sub_dirs = sub_dirs[:max_dirs]
        for sub in sub_dirs:
            folder_name = sub.rstrip("/").rsplit("/", 1)[-1]
            res = client.sync_incremental(
                dest_dir / folder_name,
                cursor,
                remote_root=sub,
                depth="1",
            )
            downloaded.extend(res["downloaded"])
            skipped.extend(res["skipped"])

    return StaSyncSummary(
        ok=True,
        wake_result=wake,
        remote_dirs=remote_dirs,
        downloaded=downloaded,
        skipped=skipped,
    )
