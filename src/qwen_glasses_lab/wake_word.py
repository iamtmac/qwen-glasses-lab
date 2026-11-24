"""0-Token 确定性端侧自定义唤醒词匹配与指令抽取器。

用于对眼镜同步音频的转写文本（或实时语音流转写结果）执行自定义唤醒词触发（例如 "Assistant"、"小助手"），
完全独立于硬件端只读 DSP 固件，可随开源套件灵活配置。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Sequence

from .config import WakeWordConfig

_LEADING_SEP_RE = re.compile(r"^[\s,，。.:：!！?？、;；\-—~～]+")


@dataclass(frozen=True)
class WakeWordMatch:
    """唤醒词命中结果。"""

    matched: bool
    wake_word: str = ""
    command_text: str = ""
    raw_text: str = ""
    match_index: int = -1


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
