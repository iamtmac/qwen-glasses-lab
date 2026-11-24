"""Fail-Closed 安全门禁：BLE GMA 指令白名单与 WebDAV HTTP 只读锁。

依据 com.alibaba.wow_1.14.0.apk 反编译源码静态实证，物理隔离任何 OTA 刷机、
关机、产测与媒体删除/写入动作。未显式列入白名单的指令或 HTTP 方法默认拒绝。
"""

from __future__ import annotations

from typing import FrozenSet, Mapping, Tuple


class UnsafeCommandBlockedError(PermissionError):
    """尝试构造或发送未授权/高危 BLE 指令时抛出的阻断异常。"""


class WriteOperationForbiddenError(PermissionError):
    """尝试对眼镜端 WebDAV 执行非只读 HTTP 方法时抛出的阻断异常。"""


# 经静态分析确认绝对禁止触碰的高危命名空间（OTA、关机、工厂测试等）
BLOCKED_BLE_NAMESPACES: Mapping[int, str] = {
    18: "OTA_NAMESPACE (0x12) - 禁止任何固件升级/擦写操作",
    21: "SHUTDOWN_NAMESPACE (0x15) - 禁止控制设备关机/重启",
    28: "FACTORY_TEST_NAMESPACE (0x1C) - 禁止产测指令",
}

# GMA_NAMESPACE (0) 中已证实属于 OTA 或高危控制的命令号
BLOCKED_GMA_COMMAND_IDS: Mapping[int, str] = {
    0x22: "OTA 固件数据包写入 (0x22 / 34)",
    0x23: "OTA 校验/确认请求 (0x23 / 35)",
    0x24: "OTA 校验响应 (0x24 / 36)",
    0x25: "OTA 状态同步 (0x25 / 37)",
    0x26: "OTA 触发升级/重传控制 (0x26 / 38)",
    0x2F: "OTA/COTA 升级控制 (0x2F / 47)",
    0x50: "GMA OTA/系统高危指令 (0x50 / 80)",
    0x51: "GMA OTA/系统高危指令 (0x51 / 81)",
    0x52: "GMA OTA/系统高危指令 (0x52 / 82)",
    0x53: "GMA OTA/系统高危指令 (0x53 / 83)",
    0x54: "GMA OTA/系统高危指令 (0x54 / 84)",
    0x55: "GMA OTA/系统高危指令 (0x55 / 85)",
}

# 严格白名单：(namespace, command_id) -> 语义说明
# 默认 Fail-Closed，未在此表中的任何组合一律阻断
ALLOWED_BLE_COMMANDS: Mapping[Tuple[int, int], str] = {
    # GMA_NAMESPACE (0)
    (0, 0x01): "GMA 能力协商/状态上报",
    (0, 0x03): "GMA 设备基础信息查询",
    (0, 0x14): "GMA 本地认证 Step1：发送 phone randomA (0x14)",
    (0, 0x16): "GMA 本地认证 Step2：发送 HMAC-SHA256 应答 (0x16)",
    (0, 0x20): "GMA 只读版本/基础参数查询 (0x20)",
    # WIFI_NAMESPACE (2) - P2P Wi-Fi Direct
    (2, 0x04): "Wi-Fi Direct GO 配对建联请求 CBOR (WifiGroup)",
    (2, 0x05): "Wi-Fi 状态/Peer 同步",
    # SET_WIFI_NAMESPACE (6) - LAN STA / 已保存 Wi-Fi 列表
    (6, 0x02): "LAN STA 局域网 Wi-Fi 连接请求 CBOR (WifiConnectRequest)",
    (6, 0x07): "查询眼镜已保存的 Wi-Fi 历史列表 (WifiRequest)",
    (6, 0x0A): "Wi-Fi 连接状态交互",
    # LONG_RECORD_NAMESPACE (22) - 仅只读同步/状态确认，禁止删除录音
    (22, 0x01): "长录音通道状态同步",
    (22, 0x03): "长录音控制状态查询",
    (22, 0x0C): "长录音断点导入元数据同步 (IMPORT_INFO)",
    # GALLERY_NAMESPACE (25) - 相册与 WebFS 服务只读触发
    (25, 0x01): "图库/WebFS 服务就绪切换 ({status:1})",
    (25, 0x03): "图库空闲传输状态交互",
    (25, 0x05): "图库缩略图只读传输控制",
}

# WebDAV 严格只读 HTTP 方法白名单
ALLOWED_READONLY_HTTP_METHODS: FrozenSet[str] = frozenset(
    {"PROPFIND", "GET", "HEAD", "OPTIONS"}
)


def is_safe_ble_command(namespace: int, command_id: int) -> bool:
    """判断 (namespace, command_id) 是否在 BLE 只读与建联安全白名单内。"""
    ns = int(namespace) & 0xFF
    cmd = int(command_id) & 0xFF
    if ns in BLOCKED_BLE_NAMESPACES:
        return False
    if ns == 0 and cmd in BLOCKED_GMA_COMMAND_IDS:
        return False
    return (ns, cmd) in ALLOWED_BLE_COMMANDS


def assert_safe_ble_command(namespace: int, command_id: int) -> str:
    """Fail-Closed 校检：不在安全白名单内的指令立即抛出 UnsafeCommandBlockedError。"""
    ns = int(namespace) & 0xFF
    cmd = int(command_id) & 0xFF
    if ns in BLOCKED_BLE_NAMESPACES:
        raise UnsafeCommandBlockedError(
            f"已拦截高危命名空间 ns={ns} (0x{ns:02X}), cmd=0x{cmd:02X}: "
            f"{BLOCKED_BLE_NAMESPACES[ns]}"
        )
    if ns == 0 and cmd in BLOCKED_GMA_COMMAND_IDS:
        raise UnsafeCommandBlockedError(
            f"已拦截高危 GMA 指令 ns=0, cmd=0x{cmd:02X}: "
            f"{BLOCKED_GMA_COMMAND_IDS[cmd]}"
        )
    key = (ns, cmd)
    if key not in ALLOWED_BLE_COMMANDS:
        raise UnsafeCommandBlockedError(
            f"Fail-Closed 拦截：未列入安全白名单的 BLE 指令 ns={ns} (0x{ns:02X}), "
            f"cmd=0x{cmd:02X}"
        )
    return ALLOWED_BLE_COMMANDS[key]


def assert_readonly_http_method(method: str) -> str:
    """校验 WebDAV 请求方法，仅允许只读枚举与下载方法。"""
    normalized = (method or "").strip().upper()
    if normalized not in ALLOWED_READONLY_HTTP_METHODS:
        raise WriteOperationForbiddenError(
            f"WebDAV 只读锁拦截：禁止使用 HTTP 方法 {normalized!r}，"
            f"仅允许 {sorted(ALLOWED_READONLY_HTTP_METHODS)}"
        )
    return normalized
