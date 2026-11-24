"""千问 AI 眼镜手机端媒体库「无线 ADB 只读增量同步器」。

设计红线（Fail-Closed）：
1. 只允许 `adb devices`、`adb shell <只读子命令>`、`adb pull` 三类动作；
   - 只读子命令限定为 `ls` / `stat` / `find` / `wc` / `echo`；
   - 任何包含 rm / mv / cp / dd / mkdir / touch / chmod / ln / push / install / reboot /
     shell 重定向 `>` / 管道写出的命令，一律在拼接阶段抛 AdbReadOnlyViolation。
2. 绝不删除、绝不写入手机端任何路径；本地落盘只发生在 synced_media/adb/ 下。
3. 增量幂等依赖 `SyncCursorStore`（size + mtime + SHA-256），二次运行跳过已落盘文件。

典型用法：
    python -m qwen_glasses_lab.adb_media_sync --dry-run --limit 5
    python -m qwen_glasses_lab.adb_media_sync --limit 20
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .webfs_readonly_client import SyncCursorStore

# ---------------------------------------------------------------------------
# 常量：手机端媒体库根目录（递归扫描各账号子目录）
# ---------------------------------------------------------------------------

DEVICE_FILES_ROOT = "/sdcard/Android/data/com.alibaba.wow/files"
DCIM_ROOT = f"{DEVICE_FILES_ROOT}/DCIM"
RECORD_ROOT = f"{DEVICE_FILES_ROOT}/ai_record"

DEFAULT_ROOTS: Tuple[str, ...] = (DCIM_ROOT, RECORD_ROOT)

# 照片 / 视频 / 录音 / 相机配置
DEFAULT_EXTS: Tuple[str, ...] = (
    ".jpg",
    ".jpeg",
    ".heic",
    ".mp4",
    ".wav",
    ".pcm",
    ".json",
)

LAB_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOCAL_DIR = LAB_ROOT / "synced_media" / "adb"
DEFAULT_CURSOR = LAB_ROOT / "synced_media" / "adb_cursor.json"
DEFAULT_ADB_BIN = LAB_ROOT / "tools" / "platform-tools" / "adb"

# 只读 shell 子命令首词白名单
_ALLOWED_SHELL_LEADERS = frozenset({"ls", "stat", "find", "wc", "echo"})

# 任何位置出现即视为写入/破坏性动作的 token（按词边界匹配）
_FORBIDDEN_TOKENS = (
    "rm",
    "rmdir",
    "mv",
    "cp",
    "dd",
    "mkdir",
    "touch",
    "chmod",
    "chown",
    "ln",
    "truncate",
    "unlink",
    "shred",
    "reboot",
    "install",
    "uninstall",
    "pm",
    "am",
    "sync",
)
_FORBIDDEN_TOKEN_RE = re.compile(r"(?:^|[\s;&|()<>])(" + "|".join(_FORBIDDEN_TOKENS) + r")(?=$|[\s;&|()<>])")


class AdbReadOnlyViolation(PermissionError):
    """试图执行非只读 ADB 指令（含删除/写入手机端）时抛出的阻断异常。"""


class AdbNotAvailableError(RuntimeError):
    """adb 可执行文件不存在或无可用设备。"""


@dataclass(frozen=True)
class RemoteMediaFile:
    """手机端单个媒体文件的只读元数据。"""

    path: str
    size: int
    mtime: int

    @property
    def fingerprint(self) -> str:
        """增量判据：mtime+size 组合指纹（等价 WebDAV 的 ETag）。"""
        return f"{self.mtime}-{self.size}"

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    @property
    def ext(self) -> str:
        dot = self.name.rfind(".")
        return self.name[dot:].lower() if dot >= 0 else ""


def assert_readonly_shell(command: str) -> str:
    """Fail-Closed 校验一条 `adb shell` 内部命令是否为纯只读。

    先遮蔽引号内内容（`stat -c '%s|%Y|%n'` 里的 `|` 不是管道），再拆分段落逐段校验，
    避免把格式串误判成命令分隔符。
    """
    text = (command or "").strip()
    if not text:
        raise AdbReadOnlyViolation("空 shell 命令被拒绝")
    masked = re.sub(r"'[^']*'|\"[^\"]*\"", " @ ", text)
    # 拆分管道 / 分号，逐段校验首词与危险 token
    for segment in re.split(r"[;&|\n]", masked):
        seg = segment.strip()
        if not seg:
            continue
        leader = seg.split()[0]
        if leader not in _ALLOWED_SHELL_LEADERS:
            raise AdbReadOnlyViolation(
                f"Fail-Closed 拦截：shell 子命令 {leader!r} 不在只读白名单 "
                f"{sorted(_ALLOWED_SHELL_LEADERS)} 内"
            )
    hit = _FORBIDDEN_TOKEN_RE.search(masked)
    if hit:
        raise AdbReadOnlyViolation(
            f"Fail-Closed 拦截：shell 命令包含破坏性/写入动作 {hit.group(1)!r}: {text[:120]}"
        )
    for redir in (">", ">>"):
        if redir in masked:
            raise AdbReadOnlyViolation(f"Fail-Closed 拦截：shell 命令包含重定向 {redir!r}")
    return text


def split_adb_output(stream: str) -> List[str]:
    """把 adb 输出按行拆分为去空行列表（兼容 CRLF）。"""
    return [line.rstrip("\r") for line in stream.splitlines() if line.strip()]


class AdbClient:
    """`tools/platform-tools/adb` 的最小只读封装（可注入 runner 便于离线单测）。"""

    def __init__(
        self,
        adb_bin: Path | str = DEFAULT_ADB_BIN,
        serial: Optional[str] = None,
        *,
        runner: Optional[Callable[[Sequence[str]], subprocess.CompletedProcess]] = None,
        timeout: float = 120.0,
    ) -> None:
        self.adb_bin = str(adb_bin)
        self.serial = serial
        self._runner = runner
        self.timeout = timeout

    # -- 底层执行 ---------------------------------------------------------
    def _exec(self, args: Sequence[str]) -> subprocess.CompletedProcess:
        argv = [self.adb_bin]
        if self.serial:
            argv += ["-s", self.serial]
        argv += list(args)
        if self._runner is not None:
            return self._runner(argv)
        if not os.path.exists(self.adb_bin):
            raise AdbNotAvailableError(f"未找到 adb 可执行文件: {self.adb_bin}")
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )

    def devices(self) -> List[str]:
        proc = self._exec(["devices"])
        online: List[str] = []
        for line in split_adb_output(proc.stdout or ""):
            if line.startswith("List of devices") or "\t" not in line:
                continue
            serial, _, state = line.partition("\t")
            if state.strip().startswith("device"):
                online.append(serial.strip())
        return online

    def ensure_device(self) -> str:
        online = self.devices()
        if not online:
            raise AdbNotAvailableError("当前没有已授权且在线的 ADB 设备，请先连接无线调试")
        if self.serial and self.serial not in online:
            raise AdbNotAvailableError(f"指定设备 {self.serial} 不在线，当前在线: {online}")
        serial = self.serial or online[0]
        self.serial = serial
        return serial

    def shell(self, command: str) -> str:
        """执行只读 shell 命令（先过白名单再下发）。"""
        checked = assert_readonly_shell(command)
        proc = self._exec(["shell", checked])
        if proc.returncode != 0:
            raise RuntimeError(
                f"adb shell 失败(rc={proc.returncode}): {checked}\n{proc.stderr or ''}"
            )
        return proc.stdout or ""

    def pull(self, remote_path: str, local_path: Path) -> None:
        """只读 `adb pull` 单文件（不触碰手机端）。"""
        local_path = Path(local_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        proc = self._exec(["pull", remote_path, str(local_path)])
        if proc.returncode != 0 or not local_path.exists():
            raise RuntimeError(
                f"adb pull 失败({remote_path} -> {local_path}): {proc.stderr or proc.stdout or ''}"
            )

    # -- 业务面 -----------------------------------------------------------
    def list_media(
        self,
        roots: Iterable[str] = DEFAULT_ROOTS,
        exts: Iterable[str] = DEFAULT_EXTS,
    ) -> List[RemoteMediaFile]:
        """用单次 `find -exec stat` 枚举所有目标扩展名文件（O(1) 往返）。"""
        ext_list = [e.lower() for e in exts]
        name_expr = " -o ".join(f"-name '*{e}'" for e in ext_list)
        found: List[RemoteMediaFile] = []
        for root in roots:
            cmd = (
                f"find {root} -type f \\( {name_expr} \\) "
                f"-exec stat -c '%s|%Y|%n' {{}} +"
            )
            out = self.shell(cmd)
            for line in split_adb_output(out):
                parts = line.split("|", 2)
                if len(parts) != 3:
                    continue
                size_s, mtime_s, path = parts
                try:
                    size = int(size_s)
                    mtime = int(float(mtime_s))
                except ValueError:
                    continue
                if path.lower().endswith(tuple(ext_list)):
                    found.append(RemoteMediaFile(path=path, size=size, mtime=mtime))
        found.sort(key=lambda f: (f.mtime, f.path))
        return found

    def remote_rel_path(self, remote_path: str) -> str:
        """把手机绝对路径转换为本地相对路径（剥掉 DEVICE_FILES_ROOT 前缀）。"""
        prefix = DEVICE_FILES_ROOT + "/"
        if remote_path.startswith(prefix):
            return remote_path[len(prefix) :]
        return remote_path.lstrip("/")


@dataclass
class SyncReport:
    """一次同步的统计结果。"""

    scanned: int = 0
    downloaded: List[str] = None  # type: ignore[assignment]
    skipped: List[str] = None  # type: ignore[assignment]
    failed: List[Tuple[str, str]] = None  # type: ignore[assignment]
    bytes_pulled: int = 0

    def __post_init__(self) -> None:
        if self.downloaded is None:
            self.downloaded = []
        if self.skipped is None:
            self.skipped = []
        if self.failed is None:
            self.failed = []

    def as_dict(self) -> Dict[str, object]:
        return {
            "scanned": self.scanned,
            "downloaded_count": len(self.downloaded),
            "skipped_count": len(self.skipped),
            "failed_count": len(self.failed),
            "bytes_pulled": self.bytes_pulled,
            "downloaded": list(self.downloaded),
            "skipped": list(self.skipped),
            "failed": [{"path": p, "error": e} for p, e in self.failed],
        }


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def sync_media(
    client: AdbClient,
    *,
    local_dir: Path = DEFAULT_LOCAL_DIR,
    cursor_path: Path = DEFAULT_CURSOR,
    roots: Iterable[str] = DEFAULT_ROOTS,
    exts: Iterable[str] = DEFAULT_EXTS,
    limit: Optional[int] = None,
    dry_run: bool = False,
    newest_first: bool = True,
    logger: Optional[Callable[[str], None]] = None,
) -> SyncReport:
    """只读增量同步手机端媒体到本地目录（幂等，绝不删除远端）。"""
    log = logger or (lambda _msg: None)
    local_dir = Path(local_dir)
    cursor = SyncCursorStore(Path(cursor_path))
    files = client.list_media(roots=roots, exts=exts)
    if newest_first:
        files.sort(key=lambda f: (f.mtime, f.path), reverse=True)
    if limit is not None and limit >= 0:
        files = files[:limit]

    report = SyncReport(scanned=len(files))
    for item in files:
        rel = client.remote_rel_path(item.path)
        dest = local_dir / rel
        if not _needs_download(cursor, item, dest):
            report.skipped.append(item.path)
            log(f"skip  {rel}")
            continue
        if dry_run:
            report.downloaded.append(item.path)
            log(f"dry   {rel}  ({item.size} B)")
            continue
        try:
            client.pull(item.path, dest)
            size = dest.stat().st_size
            if item.size and size != item.size:
                raise RuntimeError(f"落盘大小不一致: remote={item.size} local={size}")
            digest = _sha256_file(dest)
            cursor.mark_synced(
                remote_path=item.path,
                local_path=dest,
                size=size,
                etag=item.fingerprint,
                sha256=digest,
            )
            report.downloaded.append(item.path)
            report.bytes_pulled += size
            log(f"pull  {rel}  ({size} B)")
        except Exception as exc:  # noqa: BLE001 - 单文件失败不中断整体同步
            report.failed.append((item.path, str(exc)))
            log(f"FAIL  {rel}: {exc}")
    return report


def _needs_download(cursor: SyncCursorStore, item: RemoteMediaFile, dest: Path) -> bool:
    """增量判据：远端指纹一致且本地文件完整则跳过。"""
    if not dest.exists():
        return True
    rec = cursor.get(item.path)
    if rec is None:
        return True
    if rec.etag == item.fingerprint and rec.size == item.size and dest.stat().st_size == item.size:
        return False  # 远端未变且本地完整 → 跳过
    return True


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="adb_media_sync",
        description="千问 AI 眼镜手机端媒体库只读增量同步器（严禁删除/写入手机端）",
    )
    p.add_argument("--adb", default=str(DEFAULT_ADB_BIN), help="adb 可执行文件路径")
    p.add_argument("--serial", default=None, help="目标设备序列号（默认取第一个在线设备）")
    p.add_argument("--local-dir", default=str(DEFAULT_LOCAL_DIR), help="本地落盘目录")
    p.add_argument("--cursor", default=str(DEFAULT_CURSOR), help="增量游标 JSON 路径")
    p.add_argument("--root", action="append", default=None, help="手机端根目录（可重复）")
    p.add_argument("--ext", action="append", default=None, help="扩展名过滤（可重复，如 .jpg）")
    p.add_argument("--limit", type=int, default=None, help="最多处理 N 个文件（按时间倒序）")
    p.add_argument("--dry-run", action="store_true", help="只列举不下载")
    p.add_argument("--list-devices", action="store_true", help="仅打印在线设备")
    p.add_argument("--json", action="store_true", help="以 JSON 输出统计")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    adb_bin = args.adb
    if not os.path.exists(adb_bin):
        fallback = shutil.which("adb")
        if fallback:
            adb_bin = fallback
    client = AdbClient(adb_bin, args.serial)
    try:
        serial = client.ensure_device()
    except AdbNotAvailableError as exc:
        print(f"[adb_media_sync] {exc}", file=sys.stderr)
        return 2
    if args.list_devices:
        print(serial)
        return 0

    print(f"[adb_media_sync] device={serial} adb={adb_bin}")
    report = sync_media(
        client,
        local_dir=Path(args.local_dir),
        cursor_path=Path(args.cursor),
        roots=tuple(args.root) if args.root else DEFAULT_ROOTS,
        exts=tuple(args.ext) if args.ext else DEFAULT_EXTS,
        limit=args.limit,
        dry_run=args.dry_run,
        logger=lambda m: print(f"  {m}"),
    )
    summary = report.as_dict()
    if args.json:
        import json as _json

        print(_json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(
            f"[adb_media_sync] scanned={summary['scanned']} "
            f"downloaded={summary['downloaded_count']} "
            f"skipped={summary['skipped_count']} "
            f"failed={summary['failed_count']} "
            f"bytes={summary['bytes_pulled']}"
        )
    return 0 if not report.failed else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
