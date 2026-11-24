"""qwen_glasses_lab 协议编解码、密码学原语、只读同步与 Fail-Closed 安全锁单测。"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import subprocess
from pathlib import Path

import httpx
import pytest

from qwen_glasses_lab import (
    ALIBABA_CID,
    AdbClient,
    AdbReadOnlyViolation,
    assert_readonly_shell,
    build_command_frame_v1,
    decode_gcsp_v1_header,
    encode_gcsp_v1_header,
    parse_frame_v1,
    sync_media,
    DEFAULT_L2CAP_PSM,
    AISCommandHeader,
    ChannelId,
    NameSpace,
    PayloadDataType,
    RequestType,
    SyncCursorStore,
    UnsafeCommandBlockedError,
    WebFSReadOnlyClient,
    WriteOperationForbiddenError,
    assert_readonly_http_method,
    assert_safe_ble_command,
    build_command_frame_v2,
    build_gcsp_version_neg_req,
    build_raw_frame_v2,
    build_wifi_connect_request_cbor,
    build_wifi_group_cbor,
    cbor_dumps,
    cbor_loads,
    compute_local_auth_ack_hmac,
    compute_local_auth_challenge_hmac,
    crc16_ccitt,
    decode_gcsp_v2_header,
    derive_gma_aes_key,
    derive_webfs_tls_psk,
    encode_gcsp_v2_header,
    is_safe_ble_command,
    parse_frame_v2,
    parse_manufacturer_ad_data,
    parse_propfind_multistatus,
)
from qwen_glasses_lab.btsnoop_parser import parse_btsnoop_l2cap


def test_crc16_ccitt_standard_vector() -> None:
    """标准 CCITT-FALSE (init=0xFFFF, poly=0x1021) 验证，对照 GmaCrc16.a。"""
    assert crc16_ccitt(b"123456789") == 0x29B1


def test_gcsp_v2_header_and_xor_validation() -> None:
    """7 字节 GCSP V2 帧头编解码及 XOR 篡改检测。"""
    hdr_bytes = encode_gcsp_v2_header(
        channel_id=ChannelId.MESSAGE,
        frame_id=0x123,
        is_encrypted=False,
        crc16_enabled=True,
        pdu_length=42,
    )
    assert len(hdr_bytes) == 7
    assert hdr_bytes[0] == 0x7F
    assert hdr_bytes[1] == (1 | 0x40)
    hdr = decode_gcsp_v2_header(hdr_bytes)
    assert hdr.channel_id == 1
    assert hdr.frame_id == 0x123
    assert hdr.is_encrypted is False
    assert hdr.crc16_enabled is True
    assert hdr.pdu_length == 42

    tampered = bytearray(hdr_bytes)
    tampered[6] ^= 0x01
    with pytest.raises(ValueError, match="XOR"):
        decode_gcsp_v2_header(bytes(tampered))


def test_gcsp_version_neg_req() -> None:
    assert build_gcsp_version_neg_req(2) == b"GC\x00\x00\x01"


def test_ais_command_header_bitfields() -> None:
    """校验 AISCommandHeader 5 字节位域打包与拆包。"""
    ch = AISCommandHeader(
        namespace=NameSpace.SET_WIFI,
        command_id=0x02,
        msg_id=0x1A,
        req_type=RequestType.REQUEST,
        payload_type=PayloadDataType.CBOR_DATA,
        seg_offset=3,
        seg_num=7,
        version=1,
        rfu=2,
    )
    raw = ch.to_bytes()
    assert len(raw) == 5
    decoded = AISCommandHeader.from_bytes(raw)
    assert decoded == ch


def test_cbor_roundtrip_for_wifi_structs() -> None:
    """自研 CBOR 编解码器需正确处理 WifiGroup 与含负数 rssi 的 WifiConnectRequest。"""
    group_bytes = build_wifi_group_cbor(
        ssid="DIRECT-QWEN-1234",
        password="secret-pass",
        random_a="00112233445566778899aabbccddeeff",
        frequency=5180,
        business_id=3,
        trace_id="trace-1",
    )
    group_obj = cbor_loads(group_bytes)
    assert group_obj["ssid"] == "DIRECT-QWEN-1234"
    assert group_obj["frequency"] == 5180

    sta_bytes = build_wifi_connect_request_cbor(
        ssid="Office-5G",
        password="",
        random_a="ffeeddccbbaa99887766554433221100",
        rssi=-58,
        business_id=3,
        wifi_type=1,
    )
    sta_obj = cbor_loads(sta_bytes)
    assert sta_obj["ssid"] == "Office-5G"
    assert sta_obj["rssi"] == -58
    assert sta_obj["wifiType"] == 1

    sample = {"b": b"\x01\x02\x03", "flags": [True, False, None], "neg": -1000}
    assert cbor_loads(cbor_dumps(sample)) == sample

    # 真实抓包中的不定长 CBOR Map (0xBF ... 0xFF): {'businessID': 6, 'type': 1}
    indef_cbor = bytes.fromhex("bf6a627573696e657373494406647479706501ff")
    assert cbor_loads(indef_cbor) == {"businessID": 6, "type": 1}


def test_btsnoop_kframe_reassembly_and_gcsp_v1_decoding(tmp_path: Path) -> None:
    """验证 btsnoop_parser 对 LE-CoC K-frame 分包重组与 GCSP V1 不定长 CBOR 解码。"""
    btsnoop_file = tmp_path / "sample_btsnoop.log"
    records = bytearray(b"btsnoop\x00" + struct.pack(">II", 1, 1002))

    def add_acl(flags: int, l2_cid: int, l2_payload: bytes) -> None:
        l2 = struct.pack("<HH", len(l2_payload), l2_cid) + l2_payload
        acl = b"\x02" + struct.pack("<HH", 0x0005 | (0x02 << 12), len(l2)) + l2
        records.extend(struct.pack(">IIIIQ", len(acl), len(acl), flags, 0, 1000))
        records.extend(acl)

    # 1) LE Credit Based Conn Req (PSM=130, SCID=0x004A) & Rsp (DCID=0x004C, Result=0)
    add_acl(0, 0x0005, struct.pack("<BBH", 0x14, 1, 10) + struct.pack("<HHHHH", 130, 0x004A, 251, 247, 8))
    add_acl(1, 0x0005, struct.pack("<BBH", 0x15, 1, 10) + struct.pack("<HHHHH", 0x004C, 251, 247, 8, 0))

    # 2) GCSP V1 TX 拆分为两个 LE-CoC K-frame PDU（验证跨包 K-frame 重组）
    cbor_body = bytes.fromhex("bf6a627573696e657373494406647479706501ff")
    v1_cmd_hdr = AISCommandHeader(
        namespace=NameSpace.SET_WIFI,
        command_id=0x07,
        msg_id=48,
        req_type=RequestType.REQUEST,
        payload_type=PayloadDataType.CBOR_DATA,
    ).to_bytes()
    v1_pdu = v1_cmd_hdr + cbor_body
    v1_frame = bytes([0x01, (len(v1_pdu) >> 8) & 0x0F, len(v1_pdu) & 0xFF]) + v1_pdu
    kframe = struct.pack("<H", len(v1_frame)) + v1_frame
    add_acl(0, 0x004A, kframe[:15])
    add_acl(0, 0x004A, kframe[15:])

    btsnoop_file.write_bytes(bytes(records))
    parsed = parse_btsnoop_l2cap(btsnoop_file, target_psm=130)
    assert parsed["sdu_count"] == 1
    frame0 = parsed["frames"][0]
    assert frame0["gcsp"] == "v1"
    assert frame0["ns"] == NameSpace.SET_WIFI
    assert frame0["cmd"] == "0x07"
    assert frame0["cbor"] == {"businessID": 6, "type": 1}


def test_command_frame_v2_roundtrip_and_crc_tamper() -> None:
    frame = build_command_frame_v2(
        NameSpace.SET_WIFI,
        0x02,
        {"ssid": "LabWiFi", "rssi": -42},
        frame_id=9,
        msg_id=5,
        crc16_enabled=True,
    )
    parsed = parse_frame_v2(frame, has_command_header=True)
    assert parsed.header.frame_id == 9
    assert parsed.command_header is not None
    assert parsed.command_header.namespace == NameSpace.SET_WIFI
    assert parsed.command_header.command_id == 0x02
    assert parsed.command_header.payload_type == PayloadDataType.CBOR_DATA
    assert cbor_loads(parsed.payload) == {"ssid": "LabWiFi", "rssi": -42}

    bad_crc = bytearray(frame)
    bad_crc[-1] ^= 0xFF
    with pytest.raises(ValueError, match="CRC16"):
        parse_frame_v2(bytes(bad_crc))

    raw_frame = build_raw_frame_v2(b"GC\x00\x00\x01", channel_id=ChannelId.MESSAGE, frame_id=2)
    raw_parsed = parse_frame_v2(raw_frame, has_command_header=False)
    assert raw_parsed.payload == b"GC\x00\x00\x01"


def test_ble_safety_guard_fail_closed() -> None:
    """确认 Fail-Closed 门禁：拦截 OTA/关机/产测/未知指令，放行只读与建联白名单。"""
    assert is_safe_ble_command(NameSpace.GMA, 0x14)
    assert is_safe_ble_command(NameSpace.WIFI, 0x04)
    assert is_safe_ble_command(NameSpace.SET_WIFI, 0x02)
    assert is_safe_ble_command(NameSpace.GALLERY, 0x01)
    assert assert_safe_ble_command(NameSpace.GMA, 0x16)

    for ns, cmd in [
        (NameSpace.OTA, 0x01),
        (NameSpace.SHUTDOWN, 0x01),
        (NameSpace.FACTORY_TEST, 0x01),
        (NameSpace.GMA, 0x22),
        (NameSpace.GMA, 0x25),
        (NameSpace.GMA, 0x2F),
        (NameSpace.GMA, 0x50),
        (99, 0x01),  # 未知命名空间必须 Fail-Closed
        (NameSpace.GALLERY, 0x7F),  # 未知危险子命令必须拦截
    ]:
        assert not is_safe_ble_command(ns, cmd)
        with pytest.raises(UnsafeCommandBlockedError):
            build_command_frame_v2(ns, cmd, b"\x00")


def test_parse_manufacturer_ad_data() -> None:
    # CID 0x01A8 LE + "QWE" + feat=0x03 + pid=123456 (0x0001E240 LE) + reversed MAC AA:BB:CC:DD:EE:FF
    pid_le = (123456).to_bytes(4, "little")
    mac_rev = bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA])
    ad_payload = bytes([0xA8, 0x01]) + b"QWE" + bytes([0x03]) + pid_le + mac_rev
    parsed = parse_manufacturer_ad_data(ad_payload)
    assert parsed.company_id == ALIBABA_CID
    assert parsed.app_id == "QWE"
    assert parsed.pid_int == 123456
    assert parsed.mac_address == "AA:BB:CC:DD:EE:FF"
    assert DEFAULT_L2CAP_PSM == 130


def test_local_auth_hmac_and_webfs_psk_derivation() -> None:
    """对照 AuthPluginBusinessProxy 与 GMAServiceImpl.genWifiPSK 逐字校验密钥派生。"""
    ble_key_hex = "00112233445566778899aabbccddeeff" * 2  # 32B cache, 取前 16B
    key16 = bytes.fromhex(ble_key_hex)[:16]
    pid = 1000234
    mac = "AA:BB:CC:DD:EE:FF"
    random_a = bytes.fromhex("11112222333344445555666677778888")
    random_b = bytes.fromhex("9999aaaabbbbccccddddeeeeffff0000")

    digest, digest_hex_upper = compute_local_auth_challenge_hmac(pid, mac, random_a, ble_key_hex)
    expected_combine_a = f"{pid},{mac.lower()},{random_a.hex().lower()}".encode("utf-8")
    assert digest == hmac.new(key16, expected_combine_a, hashlib.sha256).digest()
    assert digest_hex_upper == digest.hex().upper()

    ack_digest = compute_local_auth_ack_hmac(pid, mac, random_b, ble_key_hex)
    expected_combine_b = f"{pid},{mac},{random_b.hex().upper()}".encode("utf-8")
    assert ack_digest == hmac.new(key16, expected_combine_b, hashlib.sha256).digest()

    aes_key = derive_gma_aes_key(ble_key_hex, random_a, random_b)
    assert len(aes_key) == 16

    psk = derive_webfs_tls_psk(
        pid_str=pid,
        mac_address=mac,
        ble_key_hex=ble_key_hex,
        nonce_phone_hex=random_a.hex(),
        nonce_glass_hex=random_b.hex(),
    )
    assert len(psk["psk_key"]) == 64  # 32 bytes uppercase hex
    assert len(psk["psk_identity"]) == 64  # SHA-256 HMAC uppercase hex
    assert psk["psk_key"] == psk["psk_key"].upper()
    assert psk["psk_identity"] == psk["psk_identity"].upper()


def test_webfs_readonly_lock_and_incremental_sync(tmp_path: Path) -> None:
    """验证 WebDAV 写操作绝对拦截 + PROPFIND 解析 + 增量游标二次跳过。"""
    for forbidden in ("PUT", "DELETE", "POST", "MKCOL", "MOVE", "COPY", "PROPPATCH"):
        with pytest.raises(WriteOperationForbiddenError):
            assert_readonly_http_method(forbidden)

    img_bytes = b"\xff\xd8\xff\xe0MOCK_JPEG_DATA_QWEN_GLASSES"
    multistatus_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/DCIM/AliCamera/</D:href>
    <D:propstat><D:prop>
      <D:resourcetype><D:collection/></D:resourcetype>
    </D:prop></D:propstat>
  </D:response>
  <D:response>
    <D:href>/DCIM/AliCamera/IMG_20260101_0001/BASE_0001.jpg</D:href>
    <D:propstat><D:prop>
      <D:displayname>BASE_0001.jpg</D:displayname>
      <D:getcontentlength>{len(img_bytes)}</D:getcontentlength>
      <D:getetag>"etag-0001"</D:getetag>
      <D:getlastmodified>Fri, 23 Nov 2026 10:00:00 GMT</D:getlastmodified>
    </D:prop></D:propstat>
  </D:response>
</D:multistatus>""".encode("utf-8")

    call_log: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        call_log.append((request.method, request.url.path))
        if request.method == "PROPFIND":
            return httpx.Response(207, content=multistatus_xml)
        if request.method == "GET" and request.url.path.endswith("BASE_0001.jpg"):
            return httpx.Response(200, content=img_bytes)
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    cursor_file = tmp_path / "cursor.json"
    download_dir = tmp_path / "media"
    cursor = SyncCursorStore(cursor_file)

    with WebFSReadOnlyClient(
        "192.168.49.36",
        port=8443,
        proto="dav",
        root_path="/DCIM/AliCamera",
        transport=transport,
    ) as client:
        with pytest.raises(WriteOperationForbiddenError):
            client.request_readonly("DELETE", "/DCIM/AliCamera/IMG_20260101_0001/BASE_0001.jpg")
        with pytest.raises(WriteOperationForbiddenError):
            client.request_readonly("PUT", "/DCIM/AliCamera/inject.bin", content=b"bad")

        parsed_entries = parse_propfind_multistatus(multistatus_xml, "/DCIM/AliCamera")
        assert len(parsed_entries) == 2
        assert parsed_entries[1].size == len(img_bytes)

        first = client.sync_incremental(download_dir, cursor, depth="2")
        assert first["downloaded"] == ["/DCIM/AliCamera/IMG_20260101_0001/BASE_0001.jpg"]
        assert first["skipped"] == []

        saved_file = download_dir / "IMG_20260101_0001" / "BASE_0001.jpg"
        assert saved_file.read_bytes() == img_bytes
        rec = cursor.get("/DCIM/AliCamera/IMG_20260101_0001/BASE_0001.jpg")
        assert rec is not None
        assert rec.sha256 == hashlib.sha256(img_bytes).hexdigest()

        # 第二次同步：仅触发 PROPFIND，不触发 GET
        second = client.sync_incremental(download_dir, cursor, depth="2")
        assert second["downloaded"] == []
        assert second["skipped"] == ["/DCIM/AliCamera/IMG_20260101_0001/BASE_0001.jpg"]

    cursor_data = json.loads(cursor_file.read_text(encoding="utf-8"))
    assert "/DCIM/AliCamera/IMG_20260101_0001/BASE_0001.jpg" in cursor_data["files"]
    assert [m for m, _ in call_log] == ["PROPFIND", "GET", "PROPFIND"]


# ---------------------------------------------------------------------------
# 无线 ADB 只读增量同步器
# ---------------------------------------------------------------------------

CAPTURE_LOG = Path(
    os.environ.get(
        "QWEN_GLASSES_BTSNOOP_LOG",
        str(Path(__file__).resolve().parents[1] / "captures" / "btsnoop_hci.log"),
    )
)


def test_adb_readonly_guard_blocks_destructive_shell() -> None:
    """Fail-Closed：一切删除/写入/重定向 shell 动作必须在拼接阶段被拦截。"""
    for ok in (
        "ls -la /sdcard/DCIM",
        "stat -c '%s|%Y|%n' /sdcard/a.jpg",
        "find /sdcard/DCIM -type f -name '*.jpg' -exec stat -c '%s|%Y|%n' {} +",
        "wc -c /sdcard/a.jpg",
    ):
        assert assert_readonly_shell(ok) == ok.strip()

    for bad in (
        "rm -rf /sdcard/Android/data/com.alibaba.wow/files/DCIM",
        "mv /sdcard/a.jpg /sdcard/b.jpg",
        "cp /sdcard/a.jpg /sdcard/b.jpg",
        "mkdir /sdcard/evil",
        "ls /sdcard && rm -rf /sdcard/DCIM",
        "find /sdcard -name '*.jpg' -exec rm {} +",
        "echo hi > /sdcard/x",
        "dd if=/dev/zero of=/sdcard/x",
        "pm uninstall com.alibaba.wow",
        "reboot",
    ):
        with pytest.raises(AdbReadOnlyViolation):
            assert_readonly_shell(bad)


def test_adb_pull_path_is_vetoed_by_whitelist_not_by_luck() -> None:
    """`adb push` 不能借 shell 白名单绕过：AdbClient 不暴露任何写入口。"""
    client = AdbClient("/nonexistent/adb", runner=lambda argv: None)  # type: ignore[arg-type]
    assert not hasattr(client, "push")
    assert not hasattr(client, "shell_write")
    with pytest.raises(AdbReadOnlyViolation):
        client.shell("rm -f /sdcard/Android/data/com.alibaba.wow/files/DCIM/x.jpg")


def test_adb_media_sync_incremental_and_idempotent(tmp_path: Path) -> None:
    """两次同步：首次全量落盘并校验 SHA-256，二次 100% 跳过；全程零写手机端命令。"""
    remote_index = {
        "/sdcard/Android/data/com.alibaba.wow/files/DCIM/100000000001/camera/IMG_A/base.jpg": b"JPEG-A",
        "/sdcard/Android/data/com.alibaba.wow/files/DCIM/100000000001/camera/IMG_A/cameraconfig.json": b'{"a":1}',
        "/sdcard/Android/data/com.alibaba.wow/files/ai_record/100000000001/r1.wav": b"RIFF-WAV",
    }
    issued: list[list[str]] = []

    def fake_runner(argv: list[str]):
        issued.append(list(argv))
        if "devices" in argv:
            return subprocess.CompletedProcess(argv, 0, "List of devices attached\n10.0.0.9:5555\tdevice\n", "")
        if "shell" in argv:
            cmd = argv[argv.index("shell") + 1]
            assert command_is_readonly(cmd), f"下发前未过只读门禁: {cmd}"
            root = cmd.split()[1].rstrip("/")
            lines = [
                f"{len(body)}|1700000000|{p}"
                for p, body in remote_index.items()
                if p.startswith(root + "/")
            ]
            return subprocess.CompletedProcess(argv, 0, "\n".join(lines) + "\n", "")
        if "pull" in argv:
            remote, local = argv[-2], Path(argv[-1])
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(remote_index[remote])
            return subprocess.CompletedProcess(argv, 0, "1 file pulled\n", "")
        return subprocess.CompletedProcess(argv, 1, "", "unsupported")

    def command_is_readonly(cmd: str) -> bool:
        try:
            assert_readonly_shell(cmd)
            return True
        except AdbReadOnlyViolation:
            return False

    client = AdbClient("/fake/adb", "10.0.0.9:5555", runner=fake_runner)
    assert client.ensure_device() == "10.0.0.9:5555"

    local_dir = tmp_path / "synced_media" / "adb"
    cursor_path = tmp_path / "adb_cursor.json"

    first = sync_media(client, local_dir=local_dir, cursor_path=cursor_path)
    assert first.scanned == 3
    assert len(first.downloaded) == 3 and first.failed == []
    assert (local_dir / "DCIM/100000000001/camera/IMG_A/base.jpg").read_bytes() == b"JPEG-A"
    assert (local_dir / "ai_record/100000000001/r1.wav").read_bytes() == b"RIFF-WAV"

    cursor_data = json.loads(cursor_path.read_text(encoding="utf-8"))
    key = "/sdcard/Android/data/com.alibaba.wow/files/ai_record/100000000001/r1.wav"
    assert cursor_data["files"][key]["sha256"] == hashlib.sha256(b"RIFF-WAV").hexdigest()

    pulls_before = sum(1 for a in issued if "pull" in a)
    second = sync_media(client, local_dir=local_dir, cursor_path=cursor_path)
    assert second.downloaded == []
    assert len(second.skipped) == 3
    assert sum(1 for a in issued if "pull" in a) == pulls_before, "二次同步不得重复 adb pull"

    # 全程不得出现任何写手机端/删除指令
    flattened = " ".join(" ".join(a) for a in issued)
    for token in (" push ", " rm ", " mv ", " mkdir "):
        assert token not in flattened


def test_adb_dry_run_never_touches_disk(tmp_path: Path) -> None:
    """--dry-run 只列举：一个文件都不落盘，游标也不生成。"""
    remote = "/sdcard/Android/data/com.alibaba.wow/files/DCIM/100000000001/thumbnail/t.jpg"

    def fake_runner(argv: list[str]):
        if "devices" in argv:
            return subprocess.CompletedProcess(argv, 0, "List of devices attached\nS1\tdevice\n", "")
        if "shell" in argv:
            cmd = argv[argv.index("shell") + 1]
            if "DCIM" not in cmd:
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 0, f"10|1700000000|{remote}\n", "")
        raise AssertionError("dry-run 不允许调用 adb pull")

    client = AdbClient("/fake/adb", runner=fake_runner)
    report = sync_media(
        client,
        local_dir=tmp_path / "out",
        cursor_path=tmp_path / "c.json",
        dry_run=True,
    )
    assert report.downloaded == [remote]
    assert not (tmp_path / "out").exists()
    assert not (tmp_path / "c.json").exists()


# ---------------------------------------------------------------------------
# GCSP V1 构帧 / 解析（可选本地抓包逐字节对拍）
# ---------------------------------------------------------------------------

_CAPTURE_CACHE: dict = {}


def _capture_frames() -> dict:
    if not CAPTURE_LOG.exists():
        pytest.skip(f"Optional local btsnoop capture fixture not present: {CAPTURE_LOG}")
    if "frames" not in _CAPTURE_CACHE:
        parsed = parse_btsnoop_l2cap(CAPTURE_LOG, include_payload=True)
        _CAPTURE_CACHE["frames"] = {f["pkt"]: f for f in parsed["frames"]}
        _CAPTURE_CACHE["parsed"] = parsed
    return _CAPTURE_CACHE


def test_gcsp_v1_header_uses_12bit_length() -> None:
    """V1 长度是 12 位（byte1 低 4 位 = 高 4 位），按 8 位解读会直接踩坑。"""
    # 真机抓包 pkt=1143 真实帧头：01 02 BB → 总长 702
    hdr = decode_gcsp_v1_header(bytes.fromhex("0102BB"))
    assert hdr.channel_id == 1
    assert hdr.pdu_length == 699  # (0x02 << 8) | 0xBB
    assert hdr.is_encrypted is False
    assert hdr.version == 0
    assert decode_gcsp_v1_header(bytes.fromhex("0104E0")).pdu_length == 1248  # 总长 1251

    assert encode_gcsp_v1_header(1, 699) == bytes.fromhex("0102BB")
    assert encode_gcsp_v1_header(1, 1248) == bytes.fromhex("0104E0")
    assert encode_gcsp_v1_header(22, 1) == bytes.fromhex("160001")
    with pytest.raises(ValueError):
        encode_gcsp_v1_header(1, 0x1000)
    with pytest.raises(ValueError, match="V2"):
        decode_gcsp_v1_header(bytes.fromhex("7F4100"))


@pytest.mark.parametrize("pkt_id", [1069, 1080, 1081, 1082, 3023, 3789])
def test_gcsp_v1_rebuild_is_bit_exact_against_real_capture(pkt_id: int) -> None:
    """用真实抓包帧反解字段，再用 build_command_frame_v1 重建 → 必须逐字节相同。"""
    frames = _capture_frames()["frames"]
    assert pkt_id in frames, f"抓包中缺少 pkt={pkt_id}"
    raw = bytes.fromhex(frames[pkt_id]["raw"])
    frame = parse_frame_v1(raw)
    ch = frame.command_header
    assert ch is not None
    rebuilt = build_command_frame_v1(
        ch.namespace,
        ch.command_id,
        frame.payload,
        channel_id=frame.header.channel_id,
        msg_id=ch.msg_id,
        req_type=ch.req_type,
        payload_type=ch.payload_type,
        is_encrypted=frame.header.is_encrypted,
        version=frame.header.version,
        flags=frame.header.flags,
    )
    assert rebuilt == raw, f"pkt={pkt_id} 重建帧与真机抓包不一致"


def test_gcsp_v1_parses_every_real_capture_sdu() -> None:
    """954 条真实 SDU 全部可解析：长度自洽 100%、全明文、通道分布固定。

    并做「非写死」动态对拍：凡是落在发送白名单内的帧，反向重建必须与原始字节完全一致；
    落在白名单外的（如设备侧 0x15/0x17 应答）必须被构帧门禁拒绝——这正好用真实流量
    证明「能重建的都是我们能合法发的」。
    """
    parsed = _capture_frames()["parsed"]
    total = 0
    by_channel: dict = {}
    encrypted = 0
    rebuild_ok = 0
    blocked = 0
    for item in parsed["frames"]:
        raw = bytes.fromhex(item["raw"])
        header = decode_gcsp_v1_header(raw)
        assert len(raw) == 3 + header.pdu_length, f"pkt={item['pkt']} 长度不自洽"
        total += 1
        by_channel[header.channel_id] = by_channel.get(header.channel_id, 0) + 1
        if header.is_encrypted:
            encrypted += 1
        if header.channel_id not in (1, 2):
            continue
        frame = parse_frame_v1(raw)
        ch = frame.command_header
        assert ch is not None
        if is_safe_ble_command(ch.namespace, ch.command_id):
            rebuilt = build_command_frame_v1(
                ch.namespace,
                ch.command_id,
                frame.payload,
                channel_id=header.channel_id,
                msg_id=ch.msg_id,
                req_type=ch.req_type,
                payload_type=ch.payload_type,
                is_encrypted=header.is_encrypted,
                version=header.version,
                flags=header.flags,
            )
            assert rebuilt == raw, f"pkt={item['pkt']} 动态重建失败"
            rebuild_ok += 1
        else:
            with pytest.raises(UnsafeCommandBlockedError):
                build_command_frame_v1(ch.namespace, ch.command_id, frame.payload)
            blocked += 1

    assert total == parsed["sdu_count"] == 954
    assert encrypted == 0, "真机线路为全明文，不得出现加密帧"
    assert by_channel == {0: 2, 1: 765, 2: 45, 22: 142}
    assert rebuild_ok >= 25, f"可重建帧过少（{rebuild_ok}），对拍失去意义"
    assert blocked >= 500, f"被拦截帧过少（{blocked}），说明白名单过于宽松"


def test_gcsp_v1_command_frame_passes_safety_guard() -> None:
    """V1 构帧同样强制过 Fail-Closed 白名单。"""
    frame = build_command_frame_v1(NameSpace.SET_WIFI, 0x07, {"businessID": 6, "type": 1}, msg_id=0x30)
    assert frame[:3] == bytes.fromhex("010018")
    parsed = parse_frame_v1(frame)
    assert parsed.command_header is not None
    assert parsed.command_header.namespace == NameSpace.SET_WIFI
    assert parsed.command_header.command_id == 0x07
    assert parsed.command_header.payload_type == PayloadDataType.CBOR_DATA
    assert cbor_loads(parsed.payload) == {"businessID": 6, "type": 1}

    for ns, cmd in [(NameSpace.OTA, 0x01), (NameSpace.SHUTDOWN, 0x01), (NameSpace.FACTORY_TEST, 0x01), (0, 0x26)]:
        with pytest.raises(UnsafeCommandBlockedError):
            build_command_frame_v1(ns, cmd, b"\x00")


# ---------------------------------------------------------------------------
# 端侧自定义唤醒词匹配与实时分发闭环
# ---------------------------------------------------------------------------


def test_wake_word_matching_word_boundary_and_longest_first() -> None:
    """长词优先且英文遵守词边界，不误触子串。"""
    from qwen_glasses_lab import WakeWordConfig, detect_wake_word

    cfg = WakeWordConfig(wake_words=["Assistant", "Hey Assistant", "小助手"])
    assert not detect_wake_word("This is an assistantship program", cfg).matched
    m1 = detect_wake_word("Hey Assistant，打开客厅灯", cfg)
    assert m1.matched is True
    assert m1.wake_word == "Hey Assistant"
    assert m1.command_text == "打开客厅灯"

    m2 = detect_wake_word("小助手：帮我记录刚才的白板内容", cfg)
    assert m2.matched is True
    assert m2.wake_word == "小助手"
    assert m2.command_text == "帮我记录刚才的白板内容"


def test_wake_word_dispatcher_ack_route_cooldown_and_tts() -> None:
    """验证 0-Token 空指令应答、指令路由、3 秒防抖冷却及 TTS 钩子。"""
    from qwen_glasses_lab import WakeWordConfig, WakeWordDispatcher

    now = [100.0]
    handled: list[str] = []
    spoken: list[str] = []

    cfg = WakeWordConfig(
        wake_words=["Jarvis", "小智"],
        cooldown_seconds=3.0,
        ack_reply="我在，请讲。",
        tts_enabled=True,
    )
    dispatcher = WakeWordDispatcher(
        cfg,
        command_handler=lambda m: (handled.append(m.command_text), f"已执行：{m.command_text}")[1],
        tts_speaker=spoken.append,
        clock=lambda: now[0],
    )

    # 1. 未命中：0-Token 静默放行
    r0 = dispatcher.handle_transcript("今天天气不错")
    assert r0.matched is False and r0.dispatched is False and r0.reason == "not_matched"
    assert handled == [] and spoken == []

    # 2. 仅喊唤醒词：0-Token 即刻应答，不触发 command_handler
    r1 = dispatcher.handle_transcript("Jarvis")
    assert r1.matched is True and r1.dispatched is True and r1.reason == "ack_only"
    assert r1.reply_text == "我在，请讲。"
    assert handled == [] and spoken == ["我在，请讲。"]

    # 3. 冷却窗口内重复相同转写：防抖拦截
    now[0] = 101.5
    r2 = dispatcher.handle_transcript("jarvis")
    assert r2.matched is True and r2.dispatched is False and r2.reason == "cooldown"
    assert len(spoken) == 1

    # 4. 冷却期过后喊「唤醒词 + 指令」：正确路由并播报
    now[0] = 105.0
    r3 = dispatcher.handle_transcript("小智，查询服务器 CPU 负载")
    assert r3.matched is True and r3.dispatched is True and r3.reason == "command_handled"
    assert r3.command_text == "查询服务器 CPU 负载"
    assert r3.reply_text == "已执行：查询服务器 CPU 负载"
    assert handled == ["查询服务器 CPU 负载"]
    assert spoken[-1] == "已执行：查询服务器 CPU 负载"


def test_wake_word_dispatcher_handler_error_degrades_safely() -> None:
    """外部指令回调异常时安全降级，绝不中断实时音频监听主循环。"""
    from qwen_glasses_lab import WakeWordConfig, WakeWordDispatcher

    def broken_handler(_match):
        raise RuntimeError("downstream unreachable")

    dispatcher = WakeWordDispatcher(
        WakeWordConfig(wake_words=["Jarvis"], tts_enabled=False),
        command_handler=broken_handler,
    )
    res = dispatcher.handle_transcript("Jarvis，重启构建节点")
    assert res.matched is True
    assert res.dispatched is True
    assert res.reason == "handler_error"
    assert "稍后再试" in res.reply_text
