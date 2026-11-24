import Foundation
import CoreBluetooth
import CryptoKit
import Security

// 千问 AI 眼镜 macOS 原生 CoreBluetooth + LE L2CAP CoC (PSM 130) 桥接实验程序
// 依据 com.alibaba.wow_1.14.0.apk 反编译发现（GattL2capManager / BleL2capClientManager）：
// - Service UUID: 0000FEB3-0000-1000-8000-00805F9B34FB
// - Write NoRsp / Trigger SMP Bond Characteristic: 0000FED7-0000-1000-8000-00805F9B34FB
// - Notify Characteristic: 0000FED8-0000-1000-8000-00805F9B34FB
// - L2CAP CoC Fixed PSM: 130 (0x0082)
// - Alibaba Manufacturer CID: 0x01A8 (Little Endian 0xA8 0x01, AppID "QWE"/"WoW")
//
// 协议实证（2026-11-24 真机 3.1MB btsnoop，954 条 PSM130 SDU 全量对拍）：
// - 线上实际跑 GCSP V1（3 字节公共头），isEncrypted 恒 0（全明文）
// - 3 字节头：[ (ver<<6)|channel, (enc<<7)|(flags<<4)|(len>>8), len&0xFF ]，len 为 12 位
// - 帧内 5 字节 AISCommandHeader：[ (rfu)|(pt<<2)|(rt<<4)|(ver<<6), (seg)|(off<<4), msgId, ns, cmd ]
//
// 安全准则：所有出站指令必须先过 BleCommandWhitelist（Fail-Closed），
// 严禁发送 OTA (18)、关机 (21)、产测 (28) 及 GMA 高危命令。

enum QwenGlassesSpec {
    static let aisPrimaryServiceUUID = CBUUID(string: "0000FEB3-0000-1000-8000-00805F9B34FB")
    static let aisWriteNoRspUUID     = CBUUID(string: "0000FED7-0000-1000-8000-00805F9B34FB")
    static let aisNotifyUUID         = CBUUID(string: "0000FED8-0000-1000-8000-00805F9B34FB")
    static let l2capPSM: CBL2CAPPSM  = 130
    static let alibabaCID: UInt16    = 0x01A8
}

enum BleGuardError: Error, CustomStringConvertible {
    case unsafeCommandBlocked(namespace: UInt8, commandId: UInt8)

    var description: String {
        switch self {
        case let .unsafeCommandBlocked(ns, cmd):
            return String(format: "Fail-Closed 拦截：ns=%d cmd=0x%02X 不在只读安全白名单内", ns, cmd)
        }
    }
}

struct BleCommandWhitelist {
    /// 与 Python safety_guard.py 严格保持一致的 Fail-Closed 白名单
    static let allowedPairs: Set<UInt16> = [
        Self.pack(0, 0x01),  // GMA 能力协商/状态上报
        Self.pack(0, 0x03),  // GMA 基础信息查询
        Self.pack(0, 0x14),  // GMA 本地认证 randomA
        Self.pack(0, 0x16),  // GMA 本地认证 HMAC
        Self.pack(0, 0x20),  // GMA 只读版本查询
        Self.pack(2, 0x04),  // WIFI P2P GO 建联 (WifiGroup CBOR)
        Self.pack(2, 0x05),  // WIFI 状态同步
        Self.pack(6, 0x02),  // LAN STA 配网连接 (WifiConnectRequest CBOR)
        Self.pack(6, 0x07),  // 查询已保存 Wi-Fi 列表
        Self.pack(6, 0x0A),  // Wi-Fi 状态交互
        Self.pack(22, 0x01), // 长录音通道状态
        Self.pack(22, 0x03), // 长录音状态查询
        Self.pack(22, 0x0C), // 长录音导入元数据同步
        Self.pack(25, 0x01), // 图库/WebFS 服务切换
        Self.pack(25, 0x03), // 图库空闲传输状态
        Self.pack(25, 0x05), // 图库缩略图传输控制
    ]

    static let blockedNamespaces: Set<UInt8> = [18, 21, 28]

    static func pack(_ ns: UInt8, _ cmd: UInt8) -> UInt16 {
        (UInt16(ns) << 8) | UInt16(cmd)
    }

    static func isSafe(namespace: UInt8, commandId: UInt8) -> Bool {
        !blockedNamespaces.contains(namespace) && allowedPairs.contains(pack(namespace, commandId))
    }

    static func assertSafe(namespace: UInt8, commandId: UInt8) throws {
        guard isSafe(namespace: namespace, commandId: commandId) else {
            throw BleGuardError.unsafeCommandBlocked(namespace: namespace, commandId: commandId)
        }
    }
}

// MARK: - GCSP V1 帧编解码（与 Python gcsp_protocol.build_command_frame_v1 同构）

struct GcspV1Frame {
    var channelId: UInt8
    var isEncrypted: Bool
    var version: UInt8
    var flags: UInt8
    var pduLength: Int
    var namespace: UInt8?
    var commandId: UInt8?
    var msgId: UInt8?
    var reqType: UInt8?
    var payloadType: UInt8?
    var payload: Data
    var raw: Data
}

enum GcspV1 {
    static let headerLen = 3
    static let commandHeaderLen = 5

    static func build(
        namespace: UInt8,
        commandId: UInt8,
        payload: Data = Data(),
        channelId: UInt8 = 1,
        msgId: UInt8 = 1,
        reqType: UInt8 = 0,
        payloadType: UInt8 = 0,
        isEncrypted: Bool = false,
        version: UInt8 = 0,
        flags: UInt8 = 0
    ) -> Data {
        let b0: UInt8 = ((version & 0x03) << 6) | (channelId & 0x3F)
        let pduLen = commandHeaderLen + payload.count
        let b1: UInt8 = ((isEncrypted ? 1 : 0) << 7) | ((flags & 0x07) << 4) | UInt8((pduLen >> 8) & 0x0F)
        let b2: UInt8 = UInt8(pduLen & 0xFF)
        let ch0: UInt8 = (payloadType & 0x03) << 2 | (reqType & 0x03) << 4 | (version & 0x03) << 6
        var out = Data([b0, b1, b2, ch0, 0x00, msgId, namespace, commandId])
        out.append(payload)
        return out
    }

    /// 从 rx 缓冲头部尝试解出一整帧；不足一帧返回 nil。
    static func takeFrame(from buffer: inout Data) -> GcspV1Frame? {
        guard buffer.count >= headerLen else { return nil }
        let b0 = buffer[buffer.startIndex]
        let b1 = buffer[buffer.startIndex + 1]
        let b2 = buffer[buffer.startIndex + 2]
        let channel = b0 & 0x3F
        let pduLen = (Int(b1 & 0x0F) << 8) | Int(b2)
        let total = headerLen + pduLen
        guard buffer.count >= total else { return nil }
        let raw = Data(buffer.prefix(total))
        buffer.removeFirst(total)
        var frame = GcspV1Frame(
            channelId: channel,
            isEncrypted: (b1 & 0x80) != 0,
            version: (b0 >> 6) & 0x03,
            flags: (b1 >> 4) & 0x07,
            pduLength: pduLen,
            namespace: nil, commandId: nil, msgId: nil, reqType: nil, payloadType: nil,
            payload: Data(), raw: raw
        )
        // 仅 ch1/ch2 承载 AISCommandHeader；ch0 是版本协商，ch22 是 TFTP 原始流
        if (channel == 1 || channel == 2), pduLen >= commandHeaderLen {
                let p = Array(raw)
            let ch0 = p[3]
            frame.payloadType = (ch0 >> 2) & 0x03
            frame.reqType = (ch0 >> 4) & 0x03
            frame.msgId = p[5]
            frame.namespace = p[6]
            frame.commandId = p[7]
            frame.payload = Data(p[(headerLen + commandHeaderLen)...])
        } else {
            frame.payload = Data(raw.dropFirst(headerLen))
        }
        return frame
    }
}

// MARK: - 广播解析

struct ManufacturerAdInfo: Encodable {
    let companyIdHex: String
    let appId: String
    let featureByte: UInt8
    let pid: UInt32
    let macAddress: String

    static func parse(data: Data) -> ManufacturerAdInfo? {
        guard data.count >= 16 else { return nil }
        let cid = UInt16(data[0]) | (UInt16(data[1]) << 8)
        guard cid == QwenGlassesSpec.alibabaCID else { return nil }
        let appId = String(data: data.subdata(in: 2..<5), encoding: .ascii) ?? "???"
        let feature = data[5]
        let pid = UInt32(data[6])
            | (UInt32(data[7]) << 8)
            | (UInt32(data[8]) << 16)
            | (UInt32(data[9]) << 24)
        let macBytes = data.subdata(in: 10..<16).reversed()
        let macStr = macBytes.map { String(format: "%02X", $0) }.joined(separator: ":")
        return ManufacturerAdInfo(
            companyIdHex: String(format: "0x%04X", cid),
            appId: appId,
            featureByte: feature,
            pid: pid,
            macAddress: macStr
        )
    }
}

// MARK: - 本地认证（0x14 / 0x15 / 0x16 / 0x17）

enum LocalAuth {
    static var bleKeyHex: String? { envHex("QWEN_GLASSES_BLE_KEY") }
    static var pidInt: String? { ProcessInfo.processInfo.environment["QWEN_GLASSES_PID"] }
    static var macAddress: String? { ProcessInfo.processInfo.environment["QWEN_GLASSES_MAC"] }

    static func envHex(_ name: String) -> String? {
        guard let raw = ProcessInfo.processInfo.environment[name] else { return nil }
        let clean = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: ":", with: "")
            .replacingOccurrences(of: "-", with: "")
        return clean.count >= 32 ? clean : nil
    }

    static func key16() -> SymmetricKey? {
        guard let hex = bleKeyHex, let data = dataFromHex(String(hex.prefix(32))) else { return nil }
        return SymmetricKey(data: data)
    }

    static func dataFromHex(_ hex: String) -> Data? {
        guard hex.count % 2 == 0 else { return nil }
        var out = Data(capacity: hex.count / 2)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let b = UInt8(hex[idx..<next], radix: 16) else { return nil }
            out.append(b)
            idx = next
        }
        return out
    }

    static func hex(_ d: Data) -> String { d.map { String(format: "%02X", $0) }.joined() }
    static func hexLower(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    static func hmac(key: SymmetricKey, message: String) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: key))
    }

    /// 0x14 期待值：HMAC(key, "pid,macLower,randomAHexLower")
    static func challengeHMAC(pid: String, mac: String, randomA: Data) -> Data? {
        guard let key = key16() else { return nil }
        return hmac(key: key, message: "\(pid),\(mac.lowercased()),\(hexLower(randomA))")
    }

    /// 0x16 应答：HMAC(key, "pid,mac,randomBHexUpper")
    static func ackHMAC(pid: String, mac: String, randomB: Data) -> Data? {
        guard let key = key16() else { return nil }
        return hmac(key: key, message: "\(pid),\(mac),\(hex(randomB))")
    }
}

// MARK: - 会话主类

final class GlassesL2capSession: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate, StreamDelegate {
    private var centralManager: CBCentralManager?
    private var targetPeripheral: CBPeripheral?
    private var writeNoRspChar: CBCharacteristic?
    private var notifyChar: CBCharacteristic?
    private var l2capChannel: CBL2CAPChannel?
    private let queue = DispatchQueue(label: "com.open.qwen_glasses_lab.ble")
    private let targetNameFilter: String?
    private let probeGcsp: Bool
    private let dumpNearby: Bool
    private var isOpeningL2cap = false
    private var seenIds: Set<UUID> = []
    private let rxBuffer = NSMutableData()

    // 会话行为
    private var onL2capOpened: (() -> Void)?
    private var pendingAuthRandomA: Data?
    private var authState: String = "idle"
    private var didSendVersionNeg = false

    init(targetNameFilter: String? = nil, probeGcsp: Bool = false, dumpNearby: Bool = false) {
        self.targetNameFilter = targetNameFilter
        self.probeGcsp = probeGcsp
        self.dumpNearby = dumpNearby
        super.init()
    }

    func startScan() {
        centralManager = CBCentralManager(delegate: self, queue: queue)
    }

    func stop() {
        l2capChannel?.inputStream.close()
        l2capChannel?.outputStream.close()
        if let p = targetPeripheral {
            centralManager?.cancelPeripheralConnection(p)
        }
        centralManager?.stopScan()
    }

    /// 注册「L2CAP 通道就绪」后的动作（先发版本协商，再执行动作）
    func onReady(_ action: @escaping () -> Void) {
        onL2capOpened = action
    }

    // -- 发送 -------------------------------------------------------------
    func sendGuardedL2capFrame(namespace: UInt8, commandId: UInt8, rawFrame: Data) throws {
        try BleCommandWhitelist.assertSafe(namespace: namespace, commandId: commandId)
        sendRawL2capBytes(rawFrame, tag: "l2cap_tx")
    }

    /// 安全发送：构帧前先过白名单
    func sendV1(
        namespace: UInt8,
        commandId: UInt8,
        payload: Data = Data(),
        channelId: UInt8 = 1,
        msgId: UInt8 = 1,
        reqType: UInt8 = 0,
        payloadType: UInt8 = 0
    ) throws {
        try BleCommandWhitelist.assertSafe(namespace: namespace, commandId: commandId)
        let frame = GcspV1.build(
            namespace: namespace,
            commandId: commandId,
            payload: payload,
            channelId: channelId,
            msgId: msgId,
            reqType: reqType,
            payloadType: payloadType
        )
        sendRawL2capBytes(frame, tag: "l2cap_tx")
    }

    /// 发送一段已构好的帧，但必须先解析出 ns/cmd 过白名单（用于 --tx-hex）
    func sendPrebuiltFrame(_ raw: Data) throws {
        guard raw.count >= GcspV1.headerLen + GcspV1.commandHeaderLen else {
            throw BleGuardError.unsafeCommandBlocked(namespace: 0xFF, commandId: 0xFF)
        }
        var buffer = raw
        guard let frame = GcspV1.takeFrame(from: &buffer), let ns = frame.namespace, let cmd = frame.commandId else {
            throw BleGuardError.unsafeCommandBlocked(namespace: 0xFF, commandId: 0xFF)
        }
        try BleCommandWhitelist.assertSafe(namespace: ns, commandId: cmd)
        sendRawL2capBytes(raw, tag: "l2cap_tx_prebuilt")
    }

    func sendVersionNegotiation() {
        // Channel 0 封装 3B V1 公共头 (00 00 05) + "GC" 00 00 01
        let verNeg = Data([0x00, 0x00, 0x05, 0x47, 0x43, 0x00, 0x00, 0x01])
        sendRawL2capBytes(verNeg, tag: "gcsp_ver_neg_tx")
    }

    // -- 本地认证 ---------------------------------------------------------
    func startLocalAuth() {
        guard let pid = LocalAuth.pidInt, let mac = LocalAuth.macAddress, LocalAuth.key16() != nil else {
            print("{\"event\":\"auth_skipped\",\"reason\":\"need QWEN_GLASSES_BLE_KEY + QWEN_GLASSES_PID + QWEN_GLASSES_MAC\"}")
            return
        }
        var randomA = Data(count: 16)
        _ = randomA.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        pendingAuthRandomA = randomA
        authState = "sent_0x14"
        print("{\"event\":\"auth_step1\",\"pid\":\(pid),\"mac\":\"\(mac)\",\"randomA\":\"\(LocalAuth.hexLower(randomA))\"}")
        do {
            try sendV1(namespace: 0, commandId: 0x14, payload: randomA, channelId: 1, msgId: 0, reqType: 0, payloadType: 0)
        } catch {
            print("{\"event\":\"auth_error\",\"msg\":\"\(error)\"}")
        }
    }

    private func handleAuthResponse(_ frame: GcspV1Frame) {
        guard let ns = frame.namespace, ns == 0 else { return }
        guard let pid = LocalAuth.pidInt, let mac = LocalAuth.macAddress else { return }

        if frame.commandId == 0x15, authState == "sent_0x14" {
            authState = "got_0x15"
            guard frame.payload.count >= 48, let randomA = pendingAuthRandomA else {
                print("{\"event\":\"auth_fail\",\"reason\":\"payload_short\",\"len\":\(frame.payload.count)}")
                return
            }
            let deviceHMAC = frame.payload.prefix(32)
            let randomB = frame.payload.subdata(in: 32..<48)
            let expected = LocalAuth.challengeHMAC(pid: pid, mac: mac, randomA: randomA)
            let ok = expected.map { Data($0) == Data(deviceHMAC) } ?? false
            print("{\"event\":\"auth_step2\",\"hmacMatch\":\(ok),\"randomB\":\"\(LocalAuth.hexLower(randomB))\"}")
            if ok, let ack = LocalAuth.ackHMAC(pid: pid, mac: mac, randomB: randomB) {
                authState = "sent_0x16"
                try? sendV1(namespace: 0, commandId: 0x16, payload: Data(ack), channelId: 1, msgId: 2, reqType: 0, payloadType: 0)
            } else {
                print("{\"event\":\"auth_fail\",\"reason\":\"hmac_mismatch_or_missing_key\"}")
            }
        } else if frame.commandId == 0x17 {
            authState = "authenticated"
            print("{\"event\":\"auth_ok\",\"note\":\"收到 0x17 确认，本地认证通过\"}")
        } else if frame.commandId == 0x02, frame.payloadType == 1 {
            emitJSONIfPossible(tag: "gma_info", payload: frame.payload)
        }
    }

    private func emitJSONIfPossible(tag: String, payload: Data) {
        guard let text = String(data: payload, encoding: .utf8), text.hasPrefix("{") else { return }
        let escaped = text.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: " ")
        print("{\"event\":\"\(tag)\",\"json\":\"\(escaped)\"}")
    }

    /// 从 JSON 遥测里挑出 Wi-Fi / WebFS 关键三元组并高亮输出
    private func inspectTelemetry(_ frame: GcspV1Frame) {
        guard let text = String(data: frame.payload, encoding: .utf8) else { return }
        let interesting = ["pskIdentity", "pskKey", "startServer", "onPskInfoChange", "rootPath", "randomB", "\"port\""]
        guard interesting.contains(where: { text.contains($0) }) else { return }
        func field(_ name: String) -> String? {
            guard let r = text.range(of: "\"\(name)\":\"") else { return nil }
            let rest = text[r.upperBound...]
            guard let end = rest.firstIndex(of: "\"") else { return nil }
            return String(rest[..<end])
        }
        let pskIdentity = field("pskIdentity") ?? ""
        let pskKey = field("pskKey") ?? ""
        let port = field("port") ?? ""
        let rootPath = field("rootPath") ?? ""
        let maskedKey = pskKey.isEmpty ? "" : String(pskKey.prefix(6)) + "…(共\(pskKey.count))"
        print("{\"event\":\"webfs_credential\",\"ns\":\(frame.namespace ?? 0),\"port\":\"\(port)\",\"pskIdentity\":\"\(pskIdentity)\",\"pskKeyMasked\":\"\(maskedKey)\",\"rootPath\":\"\(rootPath)\"}")
        if !pskKey.isEmpty {
            FileHandle.standardError.write(Data("{\"event\":\"webfs_credential_full\",\"port\":\"\(port)\",\"pskIdentity\":\"\(pskIdentity)\",\"pskKey\":\"\(pskKey)\"}\n".utf8))
        }
    }

    private func sendRawL2capBytes(_ rawFrame: Data, tag: String) {
        guard let outputStream = l2capChannel?.outputStream else {
            fputs("{\"error\":\"l2cap_channel_not_open\"}\n", stderr)
            return
        }
        let sent = rawFrame.withUnsafeBytes { ptr -> Int in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return outputStream.write(base, maxLength: rawFrame.count)
        }
        let hex = rawFrame.map { String(format: "%02X", $0) }.joined()
        print("{\"event\":\"\(tag)\",\"bytes\":\(sent),\"hex\":\"\(hex)\"}")
    }

    // MARK: - CBCentralManagerDelegate

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        let authRaw = CBManager.authorization.rawValue
        print("{\"event\":\"bt_state\",\"state\":\(central.state.rawValue),\"authorization\":\(authRaw)}")
        guard central.state == .poweredOn else { return }
        let connected = central.retrieveConnectedPeripherals(withServices: [QwenGlassesSpec.aisPrimaryServiceUUID])
        for p in connected {
            print("{\"event\":\"already_connected\",\"uuid\":\"\(p.identifier.uuidString)\",\"name\":\"\(p.name ?? "")\"}")
            if targetPeripheral == nil {
                targetPeripheral = p
                p.delegate = self
                central.connect(p, options: nil)
            }
        }
        central.scanForPeripherals(
            withServices: nil,
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
        )
        print("{\"event\":\"scan_started\",\"mode\":\"all_filtered\",\"targetService\":\"\(QwenGlassesSpec.aisPrimaryServiceUUID.uuidString)\"}")
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        let localName = (advertisementData[CBAdvertisementDataLocalNameKey] as? String) ?? peripheral.name ?? ""
        let mfgData = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data
        let mfgInfo = mfgData.flatMap { ManufacturerAdInfo.parse(data: $0) }
        let advServices = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID]) ?? []
        let hasAisService = advServices.contains(QwenGlassesSpec.aisPrimaryServiceUUID)
        let isAlibabaGlasses = (mfgInfo != nil) || hasAisService
            || localName.localizedCaseInsensitiveContains("qwen")
            || localName.localizedCaseInsensitiveContains("千问")
            || localName.localizedCaseInsensitiveContains("glasses")

        if dumpNearby {
            if RSSI.intValue > -78 && (!localName.isEmpty || !advServices.isEmpty || mfgInfo != nil) && seenIds.insert(peripheral.identifier).inserted {
                let svcStr = advServices.map { $0.uuidString }.joined(separator: ",")
                let mfgHex = mfgData?.map { String(format: "%02X", $0) }.joined() ?? ""
                print("{\"event\":\"nearby\",\"uuid\":\"\(peripheral.identifier.uuidString)\",\"name\":\"\(localName)\",\"rssi\":\(RSSI),\"services\":\"\(svcStr)\",\"mfgHex\":\"\(mfgHex)\"}")
            }
            return
        }

        if let filter = targetNameFilter {
            if !localName.localizedCaseInsensitiveContains(filter) && mfgInfo == nil {
                return
            }
        } else if !isAlibabaGlasses {
            return
        }

        if seenIds.insert(peripheral.identifier).inserted {
            let mfgHex = mfgData?.map { String(format: "%02X", $0) }.joined() ?? ""
            print("{\"event\":\"discovered\",\"uuid\":\"\(peripheral.identifier.uuidString)\",\"name\":\"\(localName)\",\"rssi\":\(RSSI),\"hasAisService\":\(hasAisService),\"appId\":\"\(mfgInfo?.appId ?? "")\",\"pid\":\(mfgInfo?.pid ?? 0),\"mac\":\"\(mfgInfo?.macAddress ?? "")\",\"mfgHex\":\"\(mfgHex)\"}")
        }

        if targetPeripheral == nil && (mfgInfo?.appId == "QWE" || mfgInfo?.appId == "WoW" || hasAisService || localName.localizedCaseInsensitiveContains("qwen") || localName.localizedCaseInsensitiveContains("千问")) {
            targetPeripheral = peripheral
            peripheral.delegate = self
            central.stopScan()
            print("{\"event\":\"connecting_gatt\",\"uuid\":\"\(peripheral.identifier.uuidString)\",\"name\":\"\(localName)\"}")
            central.connect(peripheral, options: nil)
        }
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        print("{\"event\":\"gatt_connected\",\"uuid\":\"\(peripheral.identifier.uuidString)\"}")
        peripheral.discoverServices([QwenGlassesSpec.aisPrimaryServiceUUID])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        print("{\"event\":\"gatt_connect_failed\",\"uuid\":\"\(peripheral.identifier.uuidString)\",\"msg\":\"\(error?.localizedDescription ?? "unknown")\"}")
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        print("{\"event\":\"gatt_disconnected\",\"uuid\":\"\(peripheral.identifier.uuidString)\",\"msg\":\"\(error?.localizedDescription ?? "none")\"}")
    }

    // MARK: - CBPeripheralDelegate

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        if let error = error {
            print("{\"event\":\"discover_services_error\",\"msg\":\"\(error.localizedDescription)\"}")
            return
        }
        guard let services = peripheral.services else { return }
        let uuids = services.map { $0.uuid.uuidString }.joined(separator: ",")
        print("{\"event\":\"services_discovered\",\"services\":\"\(uuids)\"}")
        for service in services where service.uuid == QwenGlassesSpec.aisPrimaryServiceUUID {
            peripheral.discoverCharacteristics(
                [QwenGlassesSpec.aisWriteNoRspUUID, QwenGlassesSpec.aisNotifyUUID],
                for: service
            )
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        if let error = error {
            print("{\"event\":\"discover_chars_error\",\"msg\":\"\(error.localizedDescription)\"}")
            return
        }
        guard let chars = service.characteristics else { return }
        let uuids = chars.map { $0.uuid.uuidString }.joined(separator: ",")
        print("{\"event\":\"chars_discovered\",\"chars\":\"\(uuids)\"}")
        for ch in chars {
            if ch.uuid == QwenGlassesSpec.aisWriteNoRspUUID {
                writeNoRspChar = ch
            } else if ch.uuid == QwenGlassesSpec.aisNotifyUUID {
                notifyChar = ch
                peripheral.setNotifyValue(true, for: ch)
            }
        }
        if !isOpeningL2cap {
            isOpeningL2cap = true
            print("{\"event\":\"opening_l2cap\",\"psm\":\(QwenGlassesSpec.l2capPSM)}")
            peripheral.openL2CAPChannel(QwenGlassesSpec.l2capPSM)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        if characteristic.uuid == QwenGlassesSpec.aisWriteNoRspUUID {
            if let error = error {
                print("{\"event\":\"fed7_read_result\",\"ok\":false,\"msg\":\"\(error.localizedDescription)\"}")
            } else {
                let hex = characteristic.value?.map { String(format: "%02X", $0) }.joined() ?? ""
                print("{\"event\":\"fed7_read_result\",\"ok\":true,\"hex\":\"\(hex)\"}")
            }
            if !isOpeningL2cap {
                isOpeningL2cap = true
                print("{\"event\":\"opening_l2cap\",\"psm\":\(QwenGlassesSpec.l2capPSM)}")
                peripheral.openL2CAPChannel(QwenGlassesSpec.l2capPSM)
            }
        } else if characteristic.uuid == QwenGlassesSpec.aisNotifyUUID, let val = characteristic.value {
            let hex = val.map { String(format: "%02X", $0) }.joined()
            print("{\"event\":\"gatt_notify\",\"hex\":\"\(hex)\"}")
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didOpen channel: CBL2CAPChannel?, error: Error?) {
        if let error = error {
            print("{\"event\":\"l2cap_open_error\",\"psm\":\(QwenGlassesSpec.l2capPSM),\"msg\":\"\(error.localizedDescription)\"}")
            return
        }
        guard let ch = channel else { return }
        l2capChannel = ch
        ch.inputStream.delegate = self
        ch.outputStream.delegate = self
        ch.inputStream.schedule(in: .main, forMode: .default)
        ch.outputStream.schedule(in: .main, forMode: .default)
        ch.inputStream.open()
        ch.outputStream.open()
        print("{\"event\":\"l2cap_opened\",\"psm\":\(ch.psm)}")

        if !didSendVersionNeg {
            didSendVersionNeg = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
                self?.sendVersionNegotiation()
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
                    self?.onL2capOpened?()
                }
            }
        }
    }

    func stream(_ aStream: Stream, handle eventCode: Stream.Event) {
        if eventCode == .hasBytesAvailable, let input = aStream as? InputStream {
            var buffer = [UInt8](repeating: 0, count: 4096)
            let readCount = input.read(&buffer, maxLength: buffer.count)
            if readCount > 0 {
                rxBuffer.append(buffer, length: readCount)
                drainFrames()
            }
        } else if eventCode == .errorOccurred {
            print("{\"event\":\"l2cap_stream_error\",\"msg\":\"\(aStream.streamError?.localizedDescription ?? "unknown")\"}")
        } else if eventCode == .endEncountered {
            print("{\"event\":\"l2cap_stream_end\"}")
        }
    }

    private func drainFrames() {
        var data = Data(referencing: rxBuffer)
        while true {
            guard let frame = GcspV1.takeFrame(from: &data) else { break }
            let hex = frame.raw.map { String(format: "%02X", $0) }.joined()
            var summary = "{\"event\":\"l2cap_rx\",\"bytes\":\(frame.raw.count),\"ch\":\(frame.channelId),\"enc\":\(frame.isEncrypted ? 1 : 0)"
            if let ns = frame.namespace, let cmd = frame.commandId {
                summary += ",\"ns\":\(ns),\"cmd\":\(cmd),\"rt\":\(frame.reqType ?? 0),\"pt\":\(frame.payloadType ?? 0)"
            }
            summary += ",\"hex\":\"\(hex)\"}"
            print(summary)

            if frame.channelId == 0 {
                let p = Array(frame.raw)
                if p.count >= 8, p[2] == 0x05, p[3] == 0x47, p[4] == 0x43 {
                    let ver = p[7]
                    let note = ver == 0 ? "glasses_selected_v1_plaintext" : "glasses_selected_v2"
                    print("{\"event\":\"gcsp_ver_neg_rx\",\"version\":\(ver),\"note\":\"\(note)\"}")
                }
                continue
            }
            if frame.namespace == 0 {
                handleAuthResponse(frame)
                continue
            }
            if frame.namespace == 23 {
                inspectTelemetry(frame)
            }
            emitJSONIfPossible(tag: "payload_json_ns\(frame.namespace ?? 0)", payload: frame.payload)
        }
        rxBuffer.setData(data)
    }
}

// MARK: - CLI

enum GlassesBleBridgeCLI {
    static func argValue(_ args: [String], _ name: String) -> String? {
        guard let idx = args.firstIndex(of: name), idx + 1 < args.count else { return nil }
        return args[idx + 1]
    }

    static func usage() -> String {
        """
        {\"status\":\"ready\",\"service\":\"\(QwenGlassesSpec.aisPrimaryServiceUUID.uuidString)\",\"psm\":\(QwenGlassesSpec.l2capPSM),\"whitelistCount\":\(BleCommandWhitelist.allowedPairs.count)}
        Usage:
          glasses-ble-bridge --scan [--name X] [--timeout N] [--probe-gcsp] [--dump-nearby]
          glasses-ble-bridge --tx-hex <HEX> [--timeout N]        # 发送单帧（先过白名单）
          glasses-ble-bridge --auth-local [--timeout N]          # 用 QWEN_GLASSES_BLE_KEY 做 0x14~0x17 认证
          glasses-ble-bridge --query-wifi-list [--timeout N]     # 发 ns=6 cmd=0x07 读已保存 Wi-Fi
          glasses-ble-bridge --gallery-start [--timeout N]       # 发 ch=2 ns=25 cmd=0x01 触发图库
          glasses-ble-bridge --session                            # stdin JSON 会话模式
        Env: QWEN_GLASSES_BLE_KEY / QWEN_GLASSES_PID / QWEN_GLASSES_MAC
        """
    }

    static func main() {
        // 支持 --out <path>：把全部 stdout/stderr 落盘（用 `open -n App --args ...` 启动时没有终端可看）
        let rawArgs = CommandLine.arguments
        if let idx = rawArgs.firstIndex(of: "--out"), idx + 1 < rawArgs.count {
            let path = rawArgs[idx + 1]
            if let fh = fopen(path, "a") {
                freopen(path, "a", stdout)
                freopen(path, "a", stderr)
                fclose(fh)
            }
        }
        setbuf(stdout, nil)
        setbuf(stderr, nil)
        let args = CommandLine.arguments
        if args.count == 1 || args.contains("--check-spec") || args.contains("--help") {
            print(usage())
            return
        }

        let timeoutSec: Double = argValue(args, "--timeout").flatMap { Double($0) } ?? 20.0
        let nameFilter = argValue(args, "--name")
        let dumpNearby = args.contains("--dump-nearby")
        let session = GlassesL2capSession(
            targetNameFilter: nameFilter,
            probeGcsp: args.contains("--probe-gcsp"),
            dumpNearby: dumpNearby
        )

        if args.contains("--scan") && !args.contains("--session") {
            session.startScan()
            DispatchQueue.main.asyncAfter(deadline: .now() + timeoutSec) {
                print("{\"event\":\"timeout_exit\",\"seconds\":\(timeoutSec)}")
                session.stop()
                exit(0)
            }
            RunLoop.main.run()
            return
        }

        // 需要建联的动作
        let txHex = argValue(args, "--tx-hex")
        let doAuth = args.contains("--auth-local")
        let queryWifi = args.contains("--query-wifi-list")
        let gallery = args.contains("--gallery-start")
        let interactive = args.contains("--session")

        if txHex == nil && !doAuth && !queryWifi && !gallery && !interactive {
            print(usage())
            return
        }

        session.onReady {
            if doAuth {
                session.startLocalAuth()
            }
            if let hexStr = txHex {
                guard let raw = LocalAuth.dataFromHex(hexStr.replacingOccurrences(of: " ", with: "")) else {
                    print("{\"event\":\"tx_hex_invalid\"}")
                    return
                }
                do {
                    try session.sendPrebuiltFrame(raw)
                } catch {
                    print("{\"event\":\"tx_blocked\",\"msg\":\"\(error)\"}")
                }
            }
            if queryWifi {
                // ns=6 cmd=0x07：CBOR 不定长 map {"businessID":6,"type":1}
                let payload = Data([0xBF, 0x6A]) + Data("businessID".utf8) + Data([0x06, 0x64]) + Data("type".utf8) + Data([0x01, 0xFF])
                do {
                    try session.sendV1(
                        namespace: 6, commandId: 0x07, payload: payload,
                        channelId: 1, msgId: 0x30, reqType: 0, payloadType: 2
                    )
                } catch {
                    print("{\"event\":\"tx_blocked\",\"msg\":\"\(error)\"}")
                }
            }
            if gallery {
                // ch=2 ns=25 cmd=0x01 载荷为 JSON 文本 {"status":1}（抓包中前缀有一字节长度 0x6C）
                let payload = Data([0x6C]) + Data("{\"status\":1}".utf8)
                do {
                    try session.sendV1(
                        namespace: 25, commandId: 0x01, payload: payload,
                        channelId: 2, msgId: 0x18, reqType: 0, payloadType: 1
                    )
                } catch {
                    print("{\"event\":\"tx_blocked\",\"msg\":\"\(error)\"}")
                }
            }
        }

        session.startScan()

        if interactive {
            DispatchQueue.global(qos: .userInitiated).async {
                while let line = readLine(strippingNewline: true) {
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    if trimmed.isEmpty { continue }
                    if trimmed == "quit" || trimmed == "exit" {
                        print("{\"event\":\"session_quit\"}")
                        exit(0)
                    }
                    if trimmed == "auth" {
                        session.startLocalAuth()
                        continue
                    }
                    if trimmed.hasPrefix("tx ") {
                        let hexStr = String(trimmed.dropFirst(3))
                        if let raw = LocalAuth.dataFromHex(hexStr) {
                            do { try session.sendPrebuiltFrame(raw) }
                            catch { print("{\"event\":\"tx_blocked\",\"msg\":\"\(error)\"}") }
                        } else {
                            print("{\"event\":\"tx_hex_invalid\"}")
                        }
                        continue
                    }
                    print("{\"event\":\"unknown_input\",\"line\":\"\(trimmed)\"}")
                }
            }
        }

        DispatchQueue.main.asyncAfter(deadline: .now() + timeoutSec) {
            print("{\"event\":\"timeout_exit\",\"seconds\":\(timeoutSec)}")
            session.stop()
            exit(0)
        }
        RunLoop.main.run()
    }
}

GlassesBleBridgeCLI.main()
