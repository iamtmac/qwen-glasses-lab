"""千问 AI 眼镜 GCSP V2 / GMA 协议编解码与本地密码学原语。

所有协议常量、比特位偏移、CRC16-CCITT、HMAC-SHA256、HKDF-SHA256（含 "gma" 与
"file_sync"）均对照 com.alibaba.wow_1.14.0.apk 反编译源码精确还原，不依赖第三方 CBOR 库。
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .safety_guard import assert_safe_ble_command

# BLE GATT UUID 与 L2CAP PSM 常量 (com.alibaba.ailabs.iot.aisbase.Constants)
AIS_PRIMARY_SERVICE_UUID = "0000FEB3-0000-1000-8000-00805F9B34FB"
AIS_WRITE_NO_RSP_UUID = "0000FED7-0000-1000-8000-00805F9B34FB"
AIS_NOTIFY_UUID = "0000FED8-0000-1000-8000-00805F9B34FB"
UUID_L2CAP = "EB3E0AF3-57F4-4789-AB55-86508580296B"
UUID_RFCOMM = "EB3E0AF3-57F4-4789-AB55-86508580296A"
ALIBABA_CID = 0x01A8  # BLE 广播 payload 小端字节为 b"\xa8\x01"
DEFAULT_L2CAP_PSM = 130  # 0x0082 (BleL2capClientManager.f / Constants.f2963a)

# GCSP V2 帧常量 (GmaFrameConstants & GmaFrameParser)
GCSP_MAGIC = 0x7F
GCSP_V2_HEADER_LEN = 7
GCSP_COMMAND_HEADER_LEN = 5
GCSP_PREAMBLE = b"GC"  # {71, 67}
GCSP_OP_VERSION_NEG_REQ = 0
GCSP_OP_VERSION_NEG_RSP = 1
CRC16_CCITT_INIT = 0xFFFF
CRC16_CCITT_POLY = 0x1021

# WebFS 常量 (GlassConnection)
WEBFS_HTTPS_PORT = 8443
WEBFS_ROOT_NEW = "/DCIM/AliCamera"
WEBFS_ROOT_OLD = "/"


class ChannelId(IntEnum):
    """GMARawData.GMAPDUChannelId 枚举。"""

    VOICE = 0
    MESSAGE = 1
    AUDIO = 2
    TRIVIAL = 3


class RequestType(IntEnum):
    """GMAMessageData.GMAPDURequestType 枚举。"""

    REQUEST = 0
    RESPONSE = 1
    NOTIFY = 2


class PayloadDataType(IntEnum):
    """GMAMessageData.GMACommandDataType 枚举。"""

    RAW_DATA = 0
    JSON_DATA = 1
    CBOR_DATA = 2


class NameSpace(IntEnum):
    """GMAMessageData.GMAPDUNameSpace 核心子集。"""

    GMA = 0
    WIFI = 2
    SET_WIFI = 6
    TRANS = 9
    OTA = 18
    SHUTDOWN = 21
    LONG_RECORD = 22
    GALLERY = 25
    FACTORY_TEST = 28


@dataclass(frozen=True)
class ManufacturerADData:
    """解析 AISManufacturerADData (阿里巴巴 CID 0x01A8, QWE 等设备广播)。"""

    company_id: int
    app_id: str
    feature_byte: int
    pid_bytes: bytes
    pid_int: int
    mac_address: str


@dataclass(frozen=True)
class AISCommandHeader:
    """GMA 指令 5 字节扩展头 (AISCommand.AISCommandHeader)。"""

    namespace: int
    command_id: int
    msg_id: int = 0
    req_type: int = RequestType.REQUEST
    payload_type: int = PayloadDataType.RAW_DATA
    seg_offset: int = 0
    seg_num: int = 0
    version: int = 0
    rfu: int = 0

    def to_bytes(self) -> bytes:
        b0 = (
            (self.rfu & 0x03)
            | ((self.payload_type & 0x03) << 2)
            | ((self.req_type & 0x03) << 4)
            | ((self.version & 0x03) << 6)
        )
        b1 = (self.seg_num & 0x0F) | ((self.seg_offset & 0x0F) << 4)
        return bytes(
            [
                b0 & 0xFF,
                b1 & 0xFF,
                self.msg_id & 0xFF,
                self.namespace & 0xFF,
                self.command_id & 0xFF,
            ]
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "AISCommandHeader":
        if len(data) < GCSP_COMMAND_HEADER_LEN:
            raise ValueError(f"AISCommandHeader 需要至少 5 字节，实际 {len(data)}")
        b0, b1, msg_id, ns, cmd = data[0], data[1], data[2], data[3], data[4]
        return cls(
            rfu=b0 & 0x03,
            payload_type=(b0 >> 2) & 0x03,
            req_type=(b0 >> 4) & 0x03,
            version=(b0 >> 6) & 0x03,
            seg_num=b1 & 0x0F,
            seg_offset=(b1 >> 4) & 0x0F,
            msg_id=msg_id,
            namespace=ns,
            command_id=cmd,
        )


@dataclass(frozen=True)
class GcspV2Header:
    """GCSP V2 7 字节物理帧头。"""

    channel_id: int
    frame_id: int
    is_encrypted: bool
    crc16_enabled: bool
    pdu_length: int
    xor_checksum: int
    is_v2: bool = True


@dataclass(frozen=True)
class FrameV2:
    """完整 GCSP V2 解析结果。"""

    header: GcspV2Header
    pdu: bytes
    command_header: Optional[AISCommandHeader]
    payload: bytes
    crc16: Optional[int]


def crc16_ccitt(data: bytes) -> int:
    """GmaCrc16.a: 精确等价于 init=0xFFFF, poly=0x1021, MSB-first CRC16-CCITT。"""
    crc = CRC16_CCITT_INIT
    for byte in data:
        crc ^= (byte & 0xFF) << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ CRC16_CCITT_POLY) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def build_gcsp_version_neg_req(max_supported_version: int = 2) -> bytes:
    """构造 GmaCapabilityNegotiator 发送的 GCSP 版本协商请求 (`47 43 00 00 01`)。"""
    if not 1 <= max_supported_version <= 255:
        raise ValueError("max_supported_version 必须在 1..255 之间")
    return GCSP_PREAMBLE + bytes([0x00, GCSP_OP_VERSION_NEG_REQ, max_supported_version - 1])


def encode_gcsp_v2_header(
    channel_id: int,
    frame_id: int,
    is_encrypted: bool,
    crc16_enabled: bool,
    pdu_length: int,
) -> bytes:
    """编码 GmaFrameParser.a 7 字节 GCSP V2 帧头（含第 7 字节 XOR 校验）。"""
    if not 0 <= channel_id <= 0x3F:
        raise ValueError("channel_id 范围应为 0..63")
    if not 0 <= frame_id <= 0x0FFF:
        raise ValueError("frame_id 范围应为 0..4095")
    if not 0 <= pdu_length <= 0x0FFF:
        raise ValueError("pdu_length 范围应为 0..4095")

    b0 = GCSP_MAGIC
    b1 = (channel_id & 0x3F) | 0x40
    b2 = (frame_id >> 8) & 0x0F
    b3 = frame_id & 0xFF
    b4 = (
        ((1 if is_encrypted else 0) << 7)
        | ((1 if crc16_enabled else 0) << 6)
        | ((pdu_length >> 8) & 0x0F)
    )
    b5 = pdu_length & 0xFF
    b6 = b0 ^ b1 ^ b2 ^ b3 ^ b4 ^ b5
    return bytes([b0, b1, b2, b3, b4, b5, b6])


def decode_gcsp_v2_header(header_bytes: bytes) -> GcspV2Header:
    """解码并校验 GCSP V2 7 字节帧头。"""
    if len(header_bytes) < GCSP_V2_HEADER_LEN:
        raise ValueError(f"GCSP V2 帧头至少 7 字节，实际 {len(header_bytes)}")
    b0, b1, b2, b3, b4, b5, b6 = header_bytes[:7]
    if b0 != GCSP_MAGIC:
        raise ValueError(f"非法 GCSP 魔数: 0x{b0:02X}, 期望 0x{GCSP_MAGIC:02X}")
    if (b1 & 0x40) == 0:
        raise ValueError("不是 GCSP V2 帧头 (V2 bit6 == 0)")
    expected_xor = b0 ^ b1 ^ b2 ^ b3 ^ b4 ^ b5
    if b6 != expected_xor:
        raise ValueError(f"帧头 XOR 校验失败: got 0x{b6:02X}, expected 0x{expected_xor:02X}")
    return GcspV2Header(
        channel_id=b1 & 0x3F,
        frame_id=((b2 & 0x0F) << 8) | b3,
        is_encrypted=bool((b4 >> 7) & 0x01),
        crc16_enabled=bool((b4 >> 6) & 0x01),
        pdu_length=((b4 & 0x0F) << 8) | b5,
        xor_checksum=b6,
        is_v2=True,
    )


def _encode_cbor_uint(major: int, value: int) -> bytes:
    prefix = major << 5
    if value < 24:
        return bytes([prefix | value])
    if value <= 0xFF:
        return bytes([prefix | 24, value])
    if value <= 0xFFFF:
        return bytes([prefix | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([prefix | 26]) + value.to_bytes(4, "big")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes([prefix | 27]) + value.to_bytes(8, "big")
    raise ValueError(f"整数超出 CBOR 64 位范围: {value}")


def cbor_dumps(obj: Any) -> bytes:
    """最小确定性 RFC 8949 CBOR 编码器（支持 int/bytes/str/list/dict/bool/None）。"""
    if obj is None:
        return b"\xf6"
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        if obj >= 0:
            return _encode_cbor_uint(0, obj)
        return _encode_cbor_uint(1, -1 - obj)
    if isinstance(obj, (bytes, bytearray)):
        raw = bytes(obj)
        return _encode_cbor_uint(2, len(raw)) + raw
    if isinstance(obj, str):
        utf8 = obj.encode("utf-8")
        return _encode_cbor_uint(3, len(utf8)) + utf8
    if isinstance(obj, (list, tuple)):
        return _encode_cbor_uint(4, len(obj)) + b"".join(cbor_dumps(item) for item in obj)
    if isinstance(obj, dict):
        items = list(obj.items())
        return _encode_cbor_uint(5, len(items)) + b"".join(
            cbor_dumps(k) + cbor_dumps(v) for k, v in items
        )
    raise TypeError(f"不支持的 CBOR 编码类型: {type(obj).__name__}")


def _decode_cbor_at(buf: memoryview, offset: int) -> Tuple[Any, int]:
    if offset >= len(buf):
        raise ValueError("CBOR 数据意外截断")
    initial = buf[offset]
    offset += 1
    major = initial >> 5
    addl = initial & 0x1F

    def _read_arg(pos: int) -> Tuple[int, int]:
        if addl < 24:
            return addl, pos
        if addl == 24:
            return buf[pos], pos + 1
        if addl == 25:
            return int.from_bytes(buf[pos : pos + 2], "big"), pos + 2
        if addl == 26:
            return int.from_bytes(buf[pos : pos + 4], "big"), pos + 4
        if addl == 27:
            return int.from_bytes(buf[pos : pos + 8], "big"), pos + 8
        raise ValueError(f"不支持的 CBOR 附加长度码: {addl}")

    if major == 0:
        val, offset = _read_arg(offset)
        return val, offset
    if major == 1:
        val, offset = _read_arg(offset)
        return -1 - val, offset
    if major == 2:
        length, offset = _read_arg(offset)
        if offset + length > len(buf):
            raise ValueError("CBOR byte string 越界")
        return bytes(buf[offset : offset + length]), offset + length
    if major == 3:
        length, offset = _read_arg(offset)
        if offset + length > len(buf):
            raise ValueError("CBOR text string 越界")
        return bytes(buf[offset : offset + length]).decode("utf-8"), offset + length
    if major == 4:
        if addl == 31:
            arr: List[Any] = []
            while offset < len(buf) and buf[offset] != 0xFF:
                item, offset = _decode_cbor_at(buf, offset)
                arr.append(item)
            if offset >= len(buf):
                raise ValueError("CBOR 不定长数组缺少 0xFF 结束符")
            return arr, offset + 1
        count, offset = _read_arg(offset)
        arr = []
        for _ in range(count):
            item, offset = _decode_cbor_at(buf, offset)
            arr.append(item)
        return arr, offset
    if major == 5:
        mapping: Dict[Any, Any] = {}
        if addl == 31:
            while offset < len(buf) and buf[offset] != 0xFF:
                key, offset = _decode_cbor_at(buf, offset)
                val, offset = _decode_cbor_at(buf, offset)
                mapping[key] = val
            if offset >= len(buf):
                raise ValueError("CBOR 不定长 Map 缺少 0xFF 结束符")
            return mapping, offset + 1
        count, offset = _read_arg(offset)
        for _ in range(count):
            key, offset = _decode_cbor_at(buf, offset)
            val, offset = _decode_cbor_at(buf, offset)
            mapping[key] = val
        return mapping, offset
    if major == 7:
        if addl == 20:
            return False, offset
        if addl == 21:
            return True, offset
        if addl == 22:
            return None, offset
    raise ValueError(f"不支持的 CBOR major={major}, addl={addl}")


def cbor_loads(data: bytes) -> Any:
    """解码 CBOR 字节流并校验无尾随垃圾字节。"""
    value, next_off = _decode_cbor_at(memoryview(data), 0)
    if next_off != len(data):
        raise ValueError(f"CBOR 解析后存在尾随字节: {next_off} != {len(data)}")
    return value


def build_command_frame_v2(
    namespace: int,
    command_id: int,
    payload: Union[bytes, dict, str, None] = None,
    *,
    channel_id: int = ChannelId.MESSAGE,
    frame_id: int = 1,
    msg_id: int = 1,
    req_type: int = RequestType.REQUEST,
    payload_type: Optional[int] = None,
    crc16_enabled: bool = True,
    is_encrypted: bool = False,
) -> bytes:
    """安全构造 GCSP V2 指令帧（自动过 Fail-Closed BLE 指令白名单门禁）。"""
    assert_safe_ble_command(namespace, command_id)

    if payload is None:
        resolved_type = PayloadDataType.RAW_DATA if payload_type is None else payload_type
        payload_bytes = b""
    elif isinstance(payload, dict):
        if payload_type == PayloadDataType.JSON_DATA:
            resolved_type = PayloadDataType.JSON_DATA
            payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
        else:
            resolved_type = PayloadDataType.CBOR_DATA if payload_type is None else payload_type
            payload_bytes = cbor_dumps(payload)
    elif isinstance(payload, str):
        resolved_type = PayloadDataType.JSON_DATA if payload_type is None else payload_type
        payload_bytes = payload.encode("utf-8")
    else:
        resolved_type = PayloadDataType.RAW_DATA if payload_type is None else payload_type
        payload_bytes = bytes(payload)

    cmd_header = AISCommandHeader(
        namespace=namespace,
        command_id=command_id,
        msg_id=msg_id,
        req_type=req_type,
        payload_type=resolved_type,
    ).to_bytes()
    pdu = cmd_header + payload_bytes
    v2_header = encode_gcsp_v2_header(
        channel_id=channel_id,
        frame_id=frame_id,
        is_encrypted=is_encrypted,
        crc16_enabled=crc16_enabled,
        pdu_length=len(pdu),
    )
    frame_body = v2_header + pdu
    if not crc16_enabled:
        return frame_body
    crc = crc16_ccitt(frame_body)
    return frame_body + bytes([(crc >> 8) & 0xFF, crc & 0xFF])


def build_raw_frame_v2(
    raw_pdu: bytes,
    *,
    channel_id: int = ChannelId.TRIVIAL,
    frame_id: int = 1,
    crc16_enabled: bool = True,
    is_encrypted: bool = False,
) -> bytes:
    """构造无 5 字节 AISCommandHeader 的 GCSP V2 原始数据帧 (serializePduRawData)。"""
    pdu = bytes(raw_pdu)
    v2_header = encode_gcsp_v2_header(
        channel_id=channel_id,
        frame_id=frame_id,
        is_encrypted=is_encrypted,
        crc16_enabled=crc16_enabled,
        pdu_length=len(pdu),
    )
    frame_body = v2_header + pdu
    if not crc16_enabled:
        return frame_body
    crc = crc16_ccitt(frame_body)
    return frame_body + bytes([(crc >> 8) & 0xFF, crc & 0xFF])


def parse_frame_v2(frame_bytes: bytes, *, has_command_header: bool = True) -> FrameV2:
    """解析并校验完整的 GCSP V2 数据帧（含头 XOR 与尾 CRC16-CCITT 校验）。"""
    header = decode_gcsp_v2_header(frame_bytes)
    expected_len = GCSP_V2_HEADER_LEN + header.pdu_length + (2 if header.crc16_enabled else 0)
    if len(frame_bytes) != expected_len:
        raise ValueError(
            f"帧长度不匹配: got {len(frame_bytes)}, expected {expected_len}"
        )
    body_end = GCSP_V2_HEADER_LEN + header.pdu_length
    crc_val: Optional[int] = None
    if header.crc16_enabled:
        crc_val = (frame_bytes[body_end] << 8) | frame_bytes[body_end + 1]
        actual_crc = crc16_ccitt(frame_bytes[:body_end])
        if crc_val != actual_crc:
            raise ValueError(
                f"CRC16-CCITT 校验失败: got 0x{crc_val:04X}, actual 0x{actual_crc:04X}"
            )

    pdu = frame_bytes[GCSP_V2_HEADER_LEN:body_end]
    if has_command_header:
        if len(pdu) < GCSP_COMMAND_HEADER_LEN:
            raise ValueError(f"PDU 长度不足以解析 AISCommandHeader: {len(pdu)}")
        cmd_header = AISCommandHeader.from_bytes(pdu[:GCSP_COMMAND_HEADER_LEN])
        payload = pdu[GCSP_COMMAND_HEADER_LEN:]
    else:
        cmd_header = None
        payload = pdu
    return FrameV2(
        header=header,
        pdu=pdu,
        command_header=cmd_header,
        payload=payload,
        crc16=crc_val,
    )


# ---------------------------------------------------------------------------
# GCSP V1：真机在线实际运行的 3 字节公共头协议（2026-11-24 抓包 954/954 帧实证）
#
#   字节 0： (version & 0x03) << 6 | (channel_id & 0x3F)
#   字节 1： (is_encrypted << 7) | (flags & 0x07) << 4 | ((pdu_len >> 8) & 0x0F)
#   字节 2： pdu_len & 0xFF
#   之后：  5 字节 AISCommandHeader + payload
#
# 关键实证：`pdu_len` 是 12 位（byte1 低 4 位是高 4 位），不是 8 位。
# 反例：抓包 pkt=1143 帧 `01 02 BB ...` 总长 702 → pdu_len = (0x02<<8)|0xBB = 699 = 702-3。
# 若按 8 位解读会得到 187，帧长直接对不上。
# ---------------------------------------------------------------------------

GCSP_V1_HEADER_LEN = 3
GCSP_V1_MAX_PDU = 0x0FFF


@dataclass(frozen=True)
class GcspV1Header:
    """GCSP V1 3 字节公共头解析结果。"""

    channel_id: int
    pdu_length: int
    is_encrypted: bool = False
    version: int = 0
    flags: int = 0


@dataclass(frozen=True)
class FrameV1:
    """完整 GCSP V1 解析结果。"""

    header: GcspV1Header
    pdu: bytes
    command_header: Optional[AISCommandHeader]
    payload: bytes


def encode_gcsp_v1_header(
    channel_id: int,
    pdu_length: int,
    *,
    is_encrypted: bool = False,
    version: int = 0,
    flags: int = 0,
) -> bytes:
    """编码 GCSP V1 3 字节公共头。"""
    if not 0 <= channel_id <= 0x3F:
        raise ValueError("channel_id 范围应为 0..63")
    if not 0 <= pdu_length <= GCSP_V1_MAX_PDU:
        raise ValueError(f"pdu_length 范围应为 0..{GCSP_V1_MAX_PDU}")
    if not 0 <= flags <= 0x07:
        raise ValueError("flags 范围应为 0..7 (3 bit)")
    if not 0 <= version <= 0x03:
        raise ValueError("version 范围应为 0..3")
    b0 = ((version & 0x03) << 6) | (channel_id & 0x3F)
    b1 = (
        ((1 if is_encrypted else 0) << 7)
        | ((flags & 0x07) << 4)
        | ((pdu_length >> 8) & 0x0F)
    )
    b2 = pdu_length & 0xFF
    return bytes([b0, b1, b2])


def decode_gcsp_v1_header(header_bytes: bytes) -> GcspV1Header:
    """解码 GCSP V1 3 字节公共头（不做长度自洽校验，交由 parse_frame_v1）。"""
    if len(header_bytes) < GCSP_V1_HEADER_LEN:
        raise ValueError(f"GCSP V1 帧头至少 3 字节，实际 {len(header_bytes)}")
    b0, b1, b2 = header_bytes[0], header_bytes[1], header_bytes[2]
    if b0 == GCSP_MAGIC:
        raise ValueError("这是 GCSP V2 帧（首字节 0x7F），请使用 parse_frame_v2")
    return GcspV1Header(
        channel_id=b0 & 0x3F,
        pdu_length=((b1 & 0x0F) << 8) | b2,
        is_encrypted=bool((b1 >> 7) & 0x01),
        version=(b0 >> 6) & 0x03,
        flags=(b1 >> 4) & 0x07,
    )


def build_command_frame_v1(
    namespace: int,
    command_id: int,
    payload: Union[bytes, dict, str, None] = None,
    *,
    channel_id: int = ChannelId.MESSAGE,
    msg_id: int = 1,
    req_type: int = RequestType.REQUEST,
    payload_type: Optional[int] = None,
    is_encrypted: bool = False,
    version: int = 0,
    flags: int = 0,
) -> bytes:
    """安全构造 GCSP V1 指令帧（自动过 Fail-Closed BLE 指令白名单门禁）。

    与 `build_command_frame_v2` 的差异：无 0x7F 魔数、无 XOR 头校验、无 CRC16 尾，
    3 字节公共头 + 5 字节 AISCommandHeader + payload，与真机抓包逐字节同构。
    """
    assert_safe_ble_command(namespace, command_id)

    if payload is None:
        resolved_type = PayloadDataType.RAW_DATA if payload_type is None else payload_type
        payload_bytes = b""
    elif isinstance(payload, dict):
        if payload_type == PayloadDataType.JSON_DATA:
            resolved_type = PayloadDataType.JSON_DATA
            payload_bytes = json.dumps(
                payload, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        else:
            resolved_type = PayloadDataType.CBOR_DATA if payload_type is None else payload_type
            payload_bytes = cbor_dumps(payload)
    elif isinstance(payload, str):
        resolved_type = PayloadDataType.JSON_DATA if payload_type is None else payload_type
        payload_bytes = payload.encode("utf-8")
    else:
        resolved_type = PayloadDataType.RAW_DATA if payload_type is None else payload_type
        payload_bytes = bytes(payload)

    cmd_header = AISCommandHeader(
        namespace=namespace,
        command_id=command_id,
        msg_id=msg_id,
        req_type=req_type,
        payload_type=resolved_type,
    ).to_bytes()
    pdu = cmd_header + payload_bytes
    header = encode_gcsp_v1_header(
        channel_id,
        len(pdu),
        is_encrypted=is_encrypted,
        version=version,
        flags=flags,
    )
    return header + pdu


def parse_frame_v1(frame_bytes: bytes, *, has_command_header: bool = True) -> FrameV1:
    """解析并校验完整的 GCSP V1 数据帧（3 字节头长度必须与整帧长度严格自洽）。"""
    header = decode_gcsp_v1_header(frame_bytes)
    expected_len = GCSP_V1_HEADER_LEN + header.pdu_length
    if len(frame_bytes) != expected_len:
        raise ValueError(
            f"GCSP V1 帧长度不匹配: got {len(frame_bytes)}, "
            f"header.pdu_length={header.pdu_length} 期望 {expected_len}"
        )
    pdu = frame_bytes[GCSP_V1_HEADER_LEN:]
    if has_command_header:
        if len(pdu) < GCSP_COMMAND_HEADER_LEN:
            raise ValueError(f"PDU 长度不足以解析 AISCommandHeader: {len(pdu)}")
        cmd_header: Optional[AISCommandHeader] = AISCommandHeader.from_bytes(
            pdu[:GCSP_COMMAND_HEADER_LEN]
        )
        payload = pdu[GCSP_COMMAND_HEADER_LEN:]
    else:
        cmd_header = None
        payload = pdu
    return FrameV1(header=header, pdu=pdu, command_header=cmd_header, payload=payload)


def parse_manufacturer_ad_data(payload: bytes) -> ManufacturerADData:
    """解析 AISManufacturerADData (0x01A8 小端前缀, 3B AppID, 1B Feature, 4B PID, 6B MAC)。"""
    if len(payload) < 16:
        raise ValueError(f"制造商广播长度不足 16 字节，实际 {len(payload)}")
    cid_le = payload[0] | (payload[1] << 8)
    if cid_le != ALIBABA_CID:
        raise ValueError(f"非阿里巴巴 BLE CID: 0x{cid_le:04X}, 期望 0x{ALIBABA_CID:04X}")
    app_id = payload[2:5].decode("ascii", errors="replace")
    feature_byte = payload[5]
    pid_bytes = payload[6:10]
    pid_int = int.from_bytes(pid_bytes, "little", signed=False)
    mac_reversed = payload[10:16]
    mac_address = ":".join(f"{b:02X}" for b in reversed(mac_reversed))
    return ManufacturerADData(
        company_id=cid_le,
        app_id=app_id,
        feature_byte=feature_byte,
        pid_bytes=pid_bytes,
        pid_int=pid_int,
        mac_address=mac_address,
    )


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256，与 Utils.f(bArr, bArr2, bArr3, i) 完全等价。"""
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return kdf.derive(ikm)


def _extract_ble_key_16b(ble_key_hex: str) -> bytes:
    clean = ble_key_hex.strip().replace(" ", "")
    raw = bytes.fromhex(clean)
    if len(raw) < 16:
        raise ValueError(f"bleKey 至少需要 16 字节 (32 hex)，当前 {len(raw)} 字节")
    return raw[:16]


def compute_local_auth_challenge_hmac(
    pid_int: Union[int, str],
    mac_address: str,
    random_a: bytes,
    ble_key_hex: str,
) -> Tuple[bytes, str]:
    """还原 AuthPluginBusinessProxy.startAuthLocal (0x14 -> 0x15 校验期待值)。

    源码规则 (AuthPluginBusinessProxy.java:1093-1102):
    combineStr = f"{pid_int},{mac_address.lower()},{ConvertUtils.b(random_a).toLowerCase()}"
    """
    if len(random_a) != 16:
        raise ValueError(f"randomA 必须为 16 字节，实际 {len(random_a)}")
    key16 = _extract_ble_key_16b(ble_key_hex)
    combine_str = f"{pid_int},{mac_address.lower()},{random_a.hex().lower()}"
    digest = hmac.new(key16, combine_str.encode("utf-8"), hashlib.sha256).digest()
    return digest, digest.hex().upper()


def compute_local_auth_ack_hmac(
    pid_int: Union[int, str],
    mac_address: str,
    random_b: bytes,
    ble_key_hex: str,
    *,
    mac_lowercase: bool = False,
) -> bytes:
    """还原 AuthPluginBusinessProxy.d.onSuccess (0x15 -> 0x16 回传 HMAC)。

    实证细节 (AuthPluginBusinessProxy.java:189-198):
    ConvertUtils.b(randomB) 返回大写 hex 且源码未对其调用 .toLowerCase()；
    this.c 按传入 mac 原样拼接。
    """
    if len(random_b) != 16:
        raise ValueError(f"randomB 必须为 16 字节，实际 {len(random_b)}")
    key16 = _extract_ble_key_16b(ble_key_hex)
    mac_part = mac_address.lower() if mac_lowercase else mac_address
    combine_str = f"{pid_int},{mac_part},{random_b.hex().upper()}"
    return hmac.new(key16, combine_str.encode("utf-8"), hashlib.sha256).digest()


def derive_gma_aes_key(ble_key_hex: str, random_a: bytes, random_b: bytes) -> bytes:
    """还原 GMA 本地认证 AES-128 会话密钥派生: HKDF(ikm=bleKey16B, salt=randomA+randomB, info=b'gma', len=16)。"""
    if len(random_a) != 16 or len(random_b) != 16:
        raise ValueError("randomA 和 randomB 均需为 16 字节")
    key16 = _extract_ble_key_16b(ble_key_hex)
    return hkdf_sha256(key16, random_a + random_b, b"gma", 16)


def derive_webfs_tls_psk(
    pid_str: Union[int, str],
    mac_address: str,
    ble_key_hex: str,
    nonce_phone_hex: str,
    nonce_glass_hex: str,
) -> Dict[str, str]:
    """还原 GMAServiceImpl.genWifiPSK (GMAServiceImpl.java:478-509)。

    - salt = bytes.fromhex(nonce_phone_hex) + bytes.fromhex(nonce_glass_hex)
    - psk_key = HKDF-SHA256(bleKey16B, salt, b"file_sync", 32).hex().upper()
    - combineStr = f"{pid_str}.{mac_address.lower()}.{nonce_phone_hex}"
    - psk_identity = HMAC-SHA256(bleKey16B, combineStr).hex().upper()
    """
    key16 = _extract_ble_key_16b(ble_key_hex)
    salt = bytes.fromhex(nonce_phone_hex) + bytes.fromhex(nonce_glass_hex)
    psk_key_bytes = hkdf_sha256(key16, salt, b"file_sync", 32)
    combine_str = f"{pid_str}.{mac_address.lower()}.{nonce_phone_hex}"
    psk_identity_bytes = hmac.new(key16, combine_str.encode("utf-8"), hashlib.sha256).digest()
    return {
        "psk_identity": psk_identity_bytes.hex().upper(),
        "psk_key": psk_key_bytes.hex().upper(),
    }


def build_wifi_group_cbor(
    *,
    ssid: str,
    password: str,
    random_a: str,
    frequency: int = 5180,
    business_id: int = 3,
    trace_id: str = "",
) -> bytes:
    """构造 WIFI_NAMESPACE (2) cmd=0x04 Wi-Fi Direct WifiGroup CBOR 载荷。"""
    payload = {
        "ssid": ssid,
        "password": password,
        "frequency": int(frequency),
        "businessID": int(business_id),
        "randomA": random_a,
        "traceID": trace_id,
    }
    return cbor_dumps(payload)


def build_wifi_connect_request_cbor(
    *,
    ssid: str,
    password: str = "",
    random_a: str,
    frequency: int = 5180,
    rssi: int = -50,
    is_encrypted: int = 1,
    business_id: int = 3,
    wifi_type: int = 1,
    trace_id: str = "",
) -> bytes:
    """构造 SET_WIFI_NAMESPACE (6) cmd=0x02 WifiConnectRequest (LAN STA) CBOR 载荷。"""
    payload = {
        "ssid": ssid,
        "password": password,
        "frequency": int(frequency),
        "rssi": int(rssi),
        "isEncrypted": int(is_encrypted),
        "businessID": int(business_id),
        "wifiType": int(wifi_type),
        "randomA": random_a,
        "traceID": trace_id,
    }
    return cbor_dumps(payload)
