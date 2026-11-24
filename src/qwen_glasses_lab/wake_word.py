"""0-Token 确定性端侧自定义唤醒词匹配与实时指令分发引擎。

用于对眼镜同步音频的转写文本（或实时语音流转写结果）执行自定义唤醒词触发（例如 "Assistant"、"小助手"），
提供防抖冷却锁、仅唤醒词 0-Token 即刻应答、自定义指令回调路由与可选本机语音播报闭环，
完全独立于硬件端只读 DSP 固件，可随开源套件灵活配置。
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from .config import WakeWordConfig

_LEADING_SEP_RE = re.compile(r"^[\s,，。.:：!！?？、;；\-—~～]+")
_TTS_STRIP_RE = re.compile(r"[#*_`>\[\]()]")


@dataclass(frozen=True)
class WakeWordMatch:
    """唤醒词命中结果。"""

    matched: bool
    wake_word: str = ""
    command_text: str = ""
    raw_text: str = ""
    match_index: int = -1


@dataclass(frozen=True)
class WakeWordDispatchResult:
    """实时唤醒词分发执行回执。"""

    matched: bool
    dispatched: bool
    reason: str
    wake_word: str = ""
    command_text: str = ""
    reply_text: str = ""
    raw_text: str = ""


def detect_wake_word(text: str, config: WakeWordConfig) -> WakeWordMatch:
    """在转写文本中检测是否命中自定义唤醒词，并剥离前导唤醒词提取纯净指令正文。"""
    raw = (text or "").strip()
    if not raw or not config.enabled or not config.wake_words:
        return WakeWordMatch(matched=False, raw_text=raw)

    haystack = raw if config.case_sensitive else raw.lower()
    # 优先按长度降序匹配，避免短词抢占长词（如 "Hey Assistant" vs "Assistant"）
    ordered_words = sorted(
        (w.strip() for w in config.wake_words if w and w.strip()),
        key=len,
        reverse=True,
    )

    for word in ordered_words:
        needle = word if config.case_sensitive else word.lower()
        # 英文单词需做词边界判断，防止 "assistantship" 误命中 "assistant"
        if needle.isascii() and needle.replace(" ", "").isalnum():
            pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(needle)}(?![A-Za-z0-9_])")
            m = pattern.search(haystack)
            idx = m.start() if m else -1
        else:
            idx = haystack.find(needle)

        if idx != -1:
            after = raw[idx + len(word) :]
            if config.strip_leading_punctuation:
                after = _LEADING_SEP_RE.sub("", after).strip()
            else:
                after = after.strip()
            return WakeWordMatch(
                matched=True,
                wake_word=word,
                command_text=after,
                raw_text=raw,
                match_index=idx,
            )

    return WakeWordMatch(matched=False, raw_text=raw)


def filter_wake_word_commands(
    utterances: Sequence[str],
    config: WakeWordConfig,
) -> list[WakeWordMatch]:
    """批量筛选命中的自定义唤醒词语音片段。"""
    results: list[WakeWordMatch] = []
    for utt in utterances:
        m = detect_wake_word(utt, config)
        if m.matched:
            results.append(m)
    return results


def speak_local_tts(text: str, *, rate: int = 210) -> bool:
    """通过 macOS 原生 say 向当前系统音频输出（含蓝牙眼镜扬声器）非阻塞播报简短应答。"""
    if os.environ.get("QWEN_GLASSES_TTS_DISABLED", "").strip() in ("1", "true", "True"):
        return False
    spoken = _TTS_STRIP_RE.sub("", (text or "").strip())[:180]
    if not spoken or not os.path.exists("/usr/bin/say"):
        return False
    try:
        subprocess.Popen(
            ["/usr/bin/say", "-r", str(max(120, min(320, int(rate)))), spoken],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except OSError:
        return False


class WakeWordDispatcher:
    """线程安全的端侧唤醒词实时触发与指令分发器。

    解决“仅配置唤醒词但未接通实时语音/转写闭环”问题：
    - 未命中唤醒词：0-Token 静默放行，不触发任何外部调用；
    - 冷却窗口内重复命中相同转写：防抖拦截，避免增量 ASR 抖动或扬声器回声自激；
    - 仅喊唤醒词（无后续指令）：0-Token 即刻返回确认应答，不浪费大模型推理；
    - 命中「唤醒词 + 指令」：路由至自定义 command_handler（可对接本地 Agent / MCP / Webhook / 设备控制）。
    """

    def __init__(
        self,
        config: WakeWordConfig,
        *,
        command_handler: Optional[Callable[[WakeWordMatch], str]] = None,
        tts_speaker: Optional[Callable[[str], object]] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self._command_handler = command_handler
        self._tts_speaker = tts_speaker or speak_local_tts
        self._clock = clock
        self._lock = threading.Lock()
        self._last_wake_at: Optional[float] = None
        self._last_wake_key: str = ""

    def handle_transcript(self, text: str) -> WakeWordDispatchResult:
        """处理单条实时语音转写文本并按需分发指令与播报应答。"""
        match = detect_wake_word(text, self.config)
        if not match.matched:
            return WakeWordDispatchResult(
                matched=False,
                dispatched=False,
                reason="not_matched",
                raw_text=match.raw_text,
            )

        now = self._clock()
        dedup_key = match.raw_text if self.config.case_sensitive else match.raw_text.lower()
        cooldown = max(0.0, float(self.config.cooldown_seconds))
        with self._lock:
            if (
                self._last_wake_at is not None
                and (now - self._last_wake_at) < cooldown
                and self._last_wake_key == dedup_key
            ):
                return WakeWordDispatchResult(
                    matched=True,
                    dispatched=False,
                    reason="cooldown",
                    wake_word=match.wake_word,
                    command_text=match.command_text,
                    raw_text=match.raw_text,
                )
            self._last_wake_at = now
            self._last_wake_key = dedup_key

        ack = (self.config.ack_reply or "我在，请讲。").strip()
        if not match.command_text:
            reply_text = ack
            reason = "ack_only"
        elif self._command_handler is None:
            reply_text = ack
            reason = "command_handled"
        else:
            try:
                reply_text = str(self._command_handler(match) or "").strip() or ack
                reason = "command_handled"
            except Exception:
                reply_text = "收到，指令处理暂时不可用，请稍后再试。"
                reason = "handler_error"

        if self.config.tts_enabled and reply_text:
            try:
                self._tts_speaker(reply_text)
            except Exception:
                pass

        return WakeWordDispatchResult(
            matched=True,
            dispatched=True,
            reason=reason,
            wake_word=match.wake_word,
            command_text=match.command_text,
            reply_text=reply_text,
            raw_text=match.raw_text,
        )
