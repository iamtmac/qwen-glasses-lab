"""解析 Android btsnoop_hci.log（RFC 1761）中的 BLE L2CAP CoC (PSM 130) 与 GCSP V1/V2 帧。

用于零 Root 蓝牙报文对拍：
1. 读取 btsnoop_hci.log 原始记录（支持从 adb bugreport zip 中直接提取）；
2. 重组 HCI ACL Data 分片（PB flag = 0x00/0x02 起始包，0x01 续包）；
3. 跟踪 LE Credit Based Connection Request/Response (CID 0x0005, Code 0x14/0x15) 识别 PSM 130 对应的动态 L2CAP CID；
4. 按 LE-CoC K-frame 长度前缀（2 字节小端 SDU Length）完整重组跨 PDU 大帧；
5. 同时解析 GCSP V1（3 字节 AISCommonHeader + 5 字节 AISCommandHeader）与 GCSP V2（0x7F）及不定长 CBOR / JSON 载荷。
"""

from __future__ import annotations

import json
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .gcsp_protocol import AISCommandHeader, cbor_loads, parse_frame_v2

BTSNOOP_MAGIC = b"btsnoop\x00"


@dataclass(frozen=True)
class L2capSduRecord:
    """按 HCI ACL + LE-CoC K-frame 完整重组后的一条 L2CAP SDU 记录。"""

    packet_index: int
    direction: str  # "TX" (Host->Controller) or "RX" (Controller->Host)
    timestamp_us: int
    handle: int
    cid: int
    payload: bytes


def extract_btsnoop_from_bugreport(zip_path: Path, dest_dir: Path) -> List[Path]:
    """从 adb bugreport 压缩包中查找并提取所有 btsnoop_hci.log 文件。"""
    extracted: List[Path] = []
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in zf.namelist():
            low = name.lower()
            if "btsnoop" in low and (low.endswith(".log") or low.endswith(".cfa") or low.endswith(".log.last")):
                out_name = name.replace("/", "_")
                out_path = dest_dir / out_name
                out_path.write_bytes(zf.read(name))
                extracted.append(out_path)
    return extracted


def _decode_sdu_summary(rec: L2capSduRecord) -> Dict[str, object]:
    item: Dict[str, object] = {
        "pkt": rec.packet_index,
        "dir": rec.direction,
        "cid": f"0x{rec.cid:04X}",
        "len": len(rec.payload),
        "hex_head": rec.payload[:24].hex().upper(),
    }
    raw = rec.payload
    if not raw:
        return item

    # GCSP V2 (0x7F 魔数且带 7B 头)
    if raw[0] == 0x7F and len(raw) >= 12 and (raw[1] & 0x40):
        item["gcsp"] = "v2"
        try:
            f = parse_frame_v2(raw, has_command_header=True)
            item["encrypted"] = f.header.is_encrypted
            if f.command_header is not None:
                item["ns"] = f.command_header.namespace
                item["cmd"] = f"0x{f.command_header.command_id:02X}"
                item["payload_type"] = f.command_header.payload_type
                if not f.header.is_encrypted and f.command_header.payload_type == 2 and f.payload:
                    try:
                        item["cbor"] = cbor_loads(f.payload)
                    except Exception:
                        pass
        except Exception:
            pass
        return item

    # GCSP V1 (3B AISCommonHeader: [ch_id | ver<<6, (enc<<7) | (rfu<<4) | len_hi, len_lo])
    ch_id = raw[0] & 0x3F
    item["gcsp"] = "v1"
    item["channel_id"] = ch_id
    if ch_id == 0 and raw[3:5] == b"GC":
        item["gcsp_neg"] = raw[3:].hex().upper()
        return item

    if ch_id in (1, 2) and len(raw) >= 8:
        is_encrypted = bool((raw[1] >> 7) & 0x01)
        pdu_len = ((raw[1] & 0x0F) << 8) | raw[2]
        cmd_hdr = AISCommandHeader.from_bytes(raw[3:8])
        pay = raw[8 : min(len(raw), 3 + pdu_len)]
        item["encrypted"] = is_encrypted
        item["ns"] = cmd_hdr.namespace
        item["cmd"] = f"0x{cmd_hdr.command_id:02X}"
        item["req_type"] = cmd_hdr.req_type
        item["payload_type"] = cmd_hdr.payload_type
        if not is_encrypted and pay:
            if cmd_hdr.payload_type == 2:
                try:
                    item["cbor"] = cbor_loads(pay)
                except Exception:
                    pass
            elif cmd_hdr.payload_type == 1 or pay[:1] in (b"{", b"["):
                txt = pay.decode("utf-8", errors="replace")
                item["text"] = txt
                if pay[:1] in (b"{", b"["):
                    try:
                        item["json"] = json.loads(txt)
                    except Exception:
                        pass
    return item


def parse_btsnoop_l2cap(
    log_path: Path, target_psm: int = 130, *, include_payload: bool = False
) -> Dict[str, object]:
    """解析 btsnoop_hci.log，定位 PSM=130 的动态 CID 并完整重组所有双向 K-frame SDU。

    `include_payload=True` 时每个 frame 额外附带 `"raw": <完整帧 hex>`，
    供与 `gcsp_protocol` 构帧结果做逐字节对拍。
    """
    raw = Path(log_path).read_bytes()
    if len(raw) < 16 or raw[:8] != BTSNOOP_MAGIC:
        raise ValueError(f"不是有效的 btsnoop 文件: {log_path}")

    version, datalink = struct.unpack(">II", raw[8:16])
    offset = 16
    pkt_idx = 0

    acl_buf: Dict[Tuple[str, int], bytearray] = {}
    acl_expected_len: Dict[Tuple[str, int], int] = {}

    pending_psm_req: Dict[Tuple[int, int], int] = {}
    psm_cids: Dict[int, set[int]] = {}

    # LE-CoC K-frame SDU 重组缓冲: (direction, handle, cid) -> bytearray
    k_buf: Dict[Tuple[str, int, int], bytearray] = {}
    k_expected_len: Dict[Tuple[str, int, int], int] = {}
    sdu_records: List[L2capSduRecord] = []

    while offset + 24 <= len(raw):
        orig_len, incl_len, flags, _drops, ts_us = struct.unpack(">IIIIQ", raw[offset : offset + 24])
        offset += 24
        if offset + incl_len > len(raw):
            break
        pkt = raw[offset : offset + incl_len]
        offset += incl_len
        pkt_idx += 1

        if not pkt:
            continue
        if datalink == 1002:
            pkt_type = pkt[0]
            body = pkt[1:]
        else:
            continue

        if pkt_type != 0x02 or len(body) < 4:
            continue

        direction = "RX" if (flags & 0x01) else "TX"
        h_pb_bc, acl_len = struct.unpack("<HH", body[:4])
        handle = h_pb_bc & 0x0FFF
        pb_flag = (h_pb_bc >> 12) & 0x03
        acl_data = body[4 : 4 + acl_len]
        key = (direction, handle)

        if pb_flag in (0x00, 0x02):
            if len(acl_data) < 4:
                continue
            l2_len, _ = struct.unpack("<HH", acl_data[:4])
            acl_buf[key] = bytearray(acl_data)
            acl_expected_len[key] = l2_len + 4
        elif pb_flag == 0x01 and key in acl_buf:
            acl_buf[key].extend(acl_data)
        else:
            continue

        if key in acl_buf and len(acl_buf[key]) >= acl_expected_len[key]:
            full = bytes(acl_buf.pop(key))
            acl_expected_len.pop(key, None)
            l2_len, l2_cid = struct.unpack("<HH", full[:4])
            l2_payload = full[4 : 4 + l2_len]

            if l2_cid == 0x0005 and len(l2_payload) >= 4:
                sig_code, sig_ident, sig_len = struct.unpack("<BBH", l2_payload[:4])
                sig_data = l2_payload[4 : 4 + sig_len]
                if sig_code == 0x14 and len(sig_data) >= 10:
                    psm, scid, _mtu, _mps, _credits = struct.unpack("<HHHHH", sig_data[:10])
                    if psm == target_psm:
                        pending_psm_req[(handle, sig_ident)] = scid
                        psm_cids.setdefault(handle, set()).add(scid)
                elif sig_code == 0x15 and len(sig_data) >= 10:
                    dcid, _mtu, _mps, _credits, result = struct.unpack("<HHHHH", sig_data[:10])
                    if (handle, sig_ident) in pending_psm_req and result == 0:
                        psm_cids.setdefault(handle, set()).add(dcid)
                continue

            if l2_cid in psm_cids.get(handle, set()):
                kk = (direction, handle, l2_cid)
                if kk not in k_buf:
                    if len(l2_payload) < 2:
                        continue
                    sdu_len = struct.unpack("<H", l2_payload[:2])[0]
                    k_buf[kk] = bytearray(l2_payload[2:])
                    k_expected_len[kk] = sdu_len
                else:
                    k_buf[kk].extend(l2_payload)

                if kk in k_buf and len(k_buf[kk]) >= k_expected_len[kk]:
                    expected_len = k_expected_len.pop(kk)
                    sdu_payload = bytes(k_buf.pop(kk))[:expected_len]
                    sdu_records.append(
                        L2capSduRecord(
                            packet_index=pkt_idx,
                            direction=direction,
                            timestamp_us=ts_us,
                            handle=handle,
                            cid=l2_cid,
                            payload=sdu_payload,
                        )
                    )

    decoded_frames = [_decode_sdu_summary(rec) for rec in sdu_records]
    if include_payload:
        for item, rec in zip(decoded_frames, sdu_records):
            item["raw"] = rec.payload.hex().upper()
    return {
        "version": version,
        "datalink": datalink,
        "total_packets": pkt_idx,
        "psm_cids": {hex(h): [hex(c) for c in sorted(cs)] for h, cs in psm_cids.items()},
        "sdu_count": len(sdu_records),
        "frames": decoded_frames,
    }
