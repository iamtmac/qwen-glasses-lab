# Qwen AI Glasses Local Sync Kit (`qwen-glasses-lab`)

面向 **千问 AI 眼镜（Qwen AI Glasses G1）** 的跨平台（macOS 优先）**本地只读互操作开发套件**（MIT License）。

无需 Root 手机、无需刷机改固件、无需依赖云端接口，即可通过 macOS 原生 `CoreBluetooth` (`LE L2CAP CoC`, `PSM 130`) 引导眼镜接入当前局域网，并通过只读 `WebDAV`（`genie_webfs`）或无线 `ADB` 安全增量同步眼镜中的照片、视频与 16kHz 录音，同时内置可配置的端侧自定义唤醒词触发引擎。

> 完整配置项说明、编排示例与常见排查请阅读：[docs/OPEN_SOURCE_USER_MANUAL.md](docs/OPEN_SOURCE_USER_MANUAL.md)

---

## 核心特性

- **双轨本地只读同步**
  - **主轨（BLE L2CAP + 局域网 STA WebDAV）**：通过 macOS 原生 Swift 桥接打开 `BLE L2CAP CoC (PSM 130)`，发送白名单 STA 配网指令引导眼镜接入同一局域网并拉起 `genie_webfs`，随后使用 `WebFSReadOnlyClient` 配合 SHA-256 增量游标实现幂等同步。
  - **辅轨（无线 ADB 只读归档）**：面向存储在手机外置目录的 16kHz 长录音（`final.wav`）与历史相册，提供只读 `ls / stat / find / pull` 增量回流。
- **Fail-Closed 安全门禁（默认拒绝）**
  - **BLE 指令白名单（`safety_guard.py`）**：严格拦截固件升级（`OTA = 18`）、关机重启（`SHUTDOWN = 21`）、产测（`FACTORY_TEST = 28`）及一切未列入白名单的控制命令。
  - **WebDAV / ADB 只读锁**：仅允许 `PROPFIND`、`GET`、`HEAD`、`OPTIONS` 与 `adb pull`，物理阻断 `DELETE`、`PUT`、`MKCOL`、`MOVE`、`POST`、`rm`、`push` 等写删操作，绝不篡改设备原件。
  - **凭据零落盘**：局域网 Wi-Fi 密码与可选 `bleKey` 仅在单次运行时内存注入，不写入配置文件、日志或同步游标。
- **0-Token 端侧自定义唤醒词匹配器**
  - 支持在转写文本流层配置任意中英文自定义唤醒词列表，长词优先、英文词边界防误触，并自动剥离前导标点输出纯净指令正文。

---

## 目录结构

```text
qwen-glasses-lab/
├── README.md                                  # 项目概览与快速上手
├── LICENSE                                    # MIT 开源协议
├── pyproject.toml                             # Python 包构建配置
├── docs/
│   └── OPEN_SOURCE_USER_MANUAL.md             # 开源使用手册（19 项配置、示例与排错）
├── src/qwen_glasses_lab/
│   ├── __init__.py                            # 统一导出入口
│   ├── config.py                              # 解耦配置模型（JSON + 环境变量）
│   ├── safety_guard.py                        # BLE 指令白名单 & WebDAV 只读方法锁
│   ├── gcsp_protocol.py                       # GCSP 帧编解码、CRC16-CCITT、HMAC/HKDF、CBOR
│   ├── sta_sync_orchestrator.py               # BLE STA 唤醒 + WebDAV 只读同步编排器
│   ├── webfs_readonly_client.py               # 只读 WebDAV 客户端、TLS-PSK 隧道 & SHA-256 游标
│   ├── adb_media_sync.py                      # 无线 ADB 只读增量媒体同步器
│   ├── btsnoop_parser.py                      # Android btsnoop_hci.log 与 LE-CoC K-frame 解析器
│   └── wake_word.py                           # 0-Token 端侧自定义唤醒词匹配与指令抽取器
├── swift_bridge/
│   ├── GlassesBleBridge.swift                 # macOS CoreBluetooth + L2CAP PSM 130 原生桥接源码
│   └── Info.plist                             # macOS 蓝牙与局域网权限声明清单
└── tests/
    └── test_protocol_and_guards.py            # 协议编解码、安全门禁、ADB/WebDAV 只读同步单测
```

---

## 快速开始

### 1. 环境要求
- macOS 13+（推荐 Apple Silicon）
- Python `>= 3.10`
- Xcode Command Line Tools（`swiftc`，用于编译原生蓝牙桥接）
- 可选：Android Platform-Tools（`adb`，用于辅轨同步）

### 2. 安装 Python 套件
```bash
git clone https://github.com/iamtmac/qwen-glasses-lab.git
cd qwen-glasses-lab
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 3. 编译 macOS 原生蓝牙桥接
```bash
cd swift_bridge
mkdir -p GlassesBLEBridge.app/Contents/MacOS
xcrun swiftc -O GlassesBleBridge.swift \
  -framework CoreBluetooth -framework CryptoKit -framework Security \
  -o GlassesBLEBridge.app/Contents/MacOS/glasses-ble-bridge
cp Info.plist GlassesBLEBridge.app/Contents/Info.plist
cp GlassesBLEBridge.app/Contents/MacOS/glasses-ble-bridge ./glasses-ble-bridge
codesign --force --deep --sign - --identifier com.open.qwen-glasses-lab.ble-bridge GlassesBLEBridge.app

# 安全白名单离线自检（不会发起蓝牙扫描）
./glasses-ble-bridge --check-spec
```

### 4. 运行离线单元测试
```bash
PYTHONPATH=src pytest tests/test_protocol_and_guards.py -v
```

---

## 合规声明

本项目基于 [MIT License](LICENSE) 开源，仅供个人对自己合法拥有的硬件设备进行本地数据备份与互操作研究使用。请严格遵守只读边界，切勿用于任何未经授权的第三方设备访问或商业滥用。
