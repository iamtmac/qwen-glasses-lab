"""开源解耦配置层：千问 AI 眼镜本地只读互操作套件配置模型。

零外部业务耦合，支持 JSON 文件与环境变量加载；严禁将 Wi-Fi 密码或设备静态密钥写入持久化配置文件。
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_WAKE_WORDS: List[str] = ["Assistant", "小助手"]
DEFAULT_MEDIA_EXTENSIONS: List[str] = [".jpg", ".jpeg", ".heic", ".mp4", ".wav", ".pcm", ".json"]


@dataclass
class WakeWordConfig:
    """端侧软唤醒词配置（作用于转写文本流与语音纪要触发，不修改硬件固件只读 KWS）。"""

    enabled: bool = True
    wake_words: List[str] = field(default_factory=lambda: list(DEFAULT_WAKE_WORDS))
    case_sensitive: bool = False
    strip_leading_punctuation: bool = True
    cooldown_seconds: float = 3.0
    ack_reply: str = "我在，请讲。"
    tts_enabled: bool = False


@dataclass
class SyncPolicyConfig:
    """只读增量同步策略配置。"""

    primary_mode: str = "ble_sta"  # "ble_sta" | "adb"
    sta_frequency_mhz: int = 5220
    sta_business_id: int = 3
    sta_wifi_type: int = 1
    ble_timeout_seconds: int = 30
    webfs_root_path: str = "/DCIM/AliCamera"
    allowed_extensions: List[str] = field(default_factory=lambda: list(DEFAULT_MEDIA_EXTENSIONS))
    readonly_enforced: bool = True  # 恒定保护字段，不可通过外部配置关闭


@dataclass
class GlassesKitConfig:
    """开源千问眼镜本地互操作套件顶层配置。"""

    device_display_name: str = "Qwen Glasses G1"
    device_name_prefix: str = "Qwen Glasses"
    target_mac: str = ""
    target_pid: int = 0
    preferred_ssid: str = ""
    bridge_binary_path: str = ""
    adb_binary_path: str = ""
    adb_serial: str = ""
    storage_dir: str = "./synced_media"
    wake_word: WakeWordConfig = field(default_factory=WakeWordConfig)
    sync_policy: SyncPolicyConfig = field(default_factory=SyncPolicyConfig)

    def to_safe_dict(self) -> Dict[str, Any]:
        """导出可安全落盘/展示的配置字典（强制保持 readonly_enforced=True 且不含密码）。"""
        data = asdict(self)
        data["sync_policy"]["readonly_enforced"] = True
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GlassesKitConfig":
        raw = data or {}
        ww_raw = raw.get("wake_word") or {}
        sp_raw = raw.get("sync_policy") or {}

        wake_words_raw = ww_raw.get("wake_words", DEFAULT_WAKE_WORDS)
        clean_wake_words = [
            str(w).strip() for w in wake_words_raw if str(w).strip()
        ] or list(DEFAULT_WAKE_WORDS)

        wake_word = WakeWordConfig(
            enabled=bool(ww_raw.get("enabled", True)),
            wake_words=clean_wake_words,
            case_sensitive=bool(ww_raw.get("case_sensitive", False)),
            strip_leading_punctuation=bool(ww_raw.get("strip_leading_punctuation", True)),
        )

        exts_raw = sp_raw.get("allowed_extensions", DEFAULT_MEDIA_EXTENSIONS)
        clean_exts = [
            (str(e).strip().lower() if str(e).strip().startswith(".") else "." + str(e).strip().lower())
            for e in exts_raw
            if str(e).strip()
        ] or list(DEFAULT_MEDIA_EXTENSIONS)

        primary_mode = str(sp_raw.get("primary_mode", "ble_sta")).strip().lower()
        if primary_mode not in ("ble_sta", "adb"):
            primary_mode = "ble_sta"

        sync_policy = SyncPolicyConfig(
            primary_mode=primary_mode,
            sta_frequency_mhz=int(sp_raw.get("sta_frequency_mhz", 5220) or 5220),
            sta_business_id=int(sp_raw.get("sta_business_id", 3) or 3),
            sta_wifi_type=int(sp_raw.get("sta_wifi_type", 1) or 1),
            ble_timeout_seconds=max(10, min(120, int(sp_raw.get("ble_timeout_seconds", 30) or 30))),
            webfs_root_path=str(sp_raw.get("webfs_root_path", "/DCIM/AliCamera") or "/DCIM/AliCamera"),
            allowed_extensions=clean_exts,
            readonly_enforced=True,
        )

        return cls(
            device_display_name=str(raw.get("device_display_name", "Qwen Glasses G1")).strip() or "Qwen Glasses G1",
            device_name_prefix=str(raw.get("device_name_prefix", "Qwen Glasses")).strip(),
            target_mac=str(raw.get("target_mac", "")).strip().upper(),
            target_pid=int(raw.get("target_pid", 0) or 0),
            preferred_ssid=str(raw.get("preferred_ssid", "")).strip(),
            bridge_binary_path=str(raw.get("bridge_binary_path", "")).strip(),
            adb_binary_path=str(raw.get("adb_binary_path", "")).strip(),
            adb_serial=str(raw.get("adb_serial", "")).strip(),
            storage_dir=str(raw.get("storage_dir", "./synced_media")).strip() or "./synced_media",
            wake_word=wake_word,
            sync_policy=sync_policy,
        )

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "GlassesKitConfig":
        """从 JSON 文件加载配置，并支持环境变量覆写（如 QWEN_GLASSES_WAKE_WORDS）。"""
        data: Dict[str, Any] = {}
        if config_path is not None and Path(config_path).exists():
            data = json.loads(Path(config_path).read_text(encoding="utf-8"))
        cfg = cls.from_dict(data)

        env_ww = os.environ.get("QWEN_GLASSES_WAKE_WORDS", "").strip()
        if env_ww:
            parsed_ww = [w.strip() for w in env_ww.split(",") if w.strip()]
            if parsed_ww:
                cfg.wake_word.wake_words = parsed_ww
        env_ssid = os.environ.get("QWEN_GLASSES_PREFERRED_SSID", "").strip()
        if env_ssid:
            cfg.preferred_ssid = env_ssid
        return cfg

    def save(self, config_path: Path) -> Path:
        """原子保存安全配置字典至本地 JSON 文件。"""
        path = Path(config_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(self.to_safe_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        os.replace(tmp, path)
        return path
