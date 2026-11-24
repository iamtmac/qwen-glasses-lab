"""千问 AI 眼镜 genie_webfs 只读 WebDAV 客户端与增量同步游标。

特性：
1. 强制只读方法锁：所有 HTTP 请求均过 assert_readonly_http_method，严禁 PUT/DELETE/MKCOL。
2. 支持标准 HTTP (dav) 与基于本机 OpenSSL 3.x TLS-PSK 隧道的 HTTPS (davs:8443)。
3. 支持 PROPFIND (Depth: 0/1/infinity) 递归枚举 /DCIM/AliCamera，并按 ETag/Size/SHA-256 做本地增量同步。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx

from .safety_guard import assert_readonly_http_method

DAV_NS = "{DAV:}"


@dataclass(frozen=True)
class WebFSFileEntry:
    """WebDAV PROPFIND 解析出的文件/目录条目。"""

    href: str
    path: str
    name: str
    is_dir: bool
    size: int = 0
    etag: str = ""
    last_modified: str = ""
    creation_date: str = ""


@dataclass(frozen=True)
class SyncedFileRecord:
    """本地同步游标中记录的已落盘文件指纹。"""

    remote_path: str
    local_path: str
    size: int
    etag: str
    sha256: str
    synced_at: str


def parse_propfind_multistatus(xml_bytes: bytes, base_root: str = "/") -> List[WebFSFileEntry]:
    """解析 WebDAV 207 Multi-Status XML 响应为标准 WebFSFileEntry 列表。"""
    root_elem = ET.fromstring(xml_bytes)
    entries: List[WebFSFileEntry] = []
    norm_root = "/" + base_root.strip("/")
    if norm_root != "/":
        norm_root = norm_root.rstrip("/")

    for resp in root_elem.findall(f".//{DAV_NS}response"):
        href_elem = resp.find(f"{DAV_NS}href")
        if href_elem is None or not href_elem.text:
            continue
        raw_href = href_elem.text.strip()
        parsed = urllib.parse.urlparse(raw_href)
        path = urllib.parse.unquote(parsed.path or "/")
        if not path.startswith("/"):
            path = "/" + path

        prop = resp.find(f".//{DAV_NS}propstat/{DAV_NS}prop")
        if prop is None:
            continue

        res_type = prop.find(f"{DAV_NS}resourcetype")
        is_dir = res_type is not None and res_type.find(f"{DAV_NS}collection") is not None

        display_elem = prop.find(f"{DAV_NS}displayname")
        clean_path = path.rstrip("/") or "/"
        name = (
            display_elem.text.strip()
            if display_elem is not None and display_elem.text
            else (clean_path.rsplit("/", 1)[-1] or "/")
        )

        len_elem = prop.find(f"{DAV_NS}getcontentlength")
        size = int(len_elem.text.strip()) if len_elem is not None and len_elem.text else 0

        etag_elem = prop.find(f"{DAV_NS}getetag")
        etag = etag_elem.text.strip().strip('"') if etag_elem is not None and etag_elem.text else ""

        mod_elem = prop.find(f"{DAV_NS}getlastmodified")
        last_mod = mod_elem.text.strip() if mod_elem is not None and mod_elem.text else ""

        cre_elem = prop.find(f"{DAV_NS}creationdate")
        created = cre_elem.text.strip() if cre_elem is not None and cre_elem.text else ""

        entries.append(
            WebFSFileEntry(
                href=raw_href,
                path=clean_path,
                name=name,
                is_dir=is_dir,
                size=size,
                etag=etag,
                last_modified=last_mod,
                creation_date=created,
            )
        )
    return entries


class SyncCursorStore:
    """持久化只读增量同步游标，避免重复拉取且不删除眼镜端文件。"""

    def __init__(self, cursor_path: Path) -> None:
        self.cursor_path = Path(cursor_path)
        self._records: Dict[str, SyncedFileRecord] = {}
        self.load()

    def load(self) -> None:
        if not self.cursor_path.exists():
            self._records = {}
            return
        raw = json.loads(self.cursor_path.read_text(encoding="utf-8"))
        self._records = {
            k: SyncedFileRecord(**v) for k, v in raw.get("files", {}).items()
        }

    def save(self) -> None:
        self.cursor_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "files": {k: asdict(v) for k, v in sorted(self._records.items())},
        }
        tmp = self.cursor_path.with_suffix(self.cursor_path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.cursor_path)

    def get(self, remote_path: str) -> Optional[SyncedFileRecord]:
        return self._records.get(remote_path)

    def needs_download(self, entry: WebFSFileEntry, dest_path: Path) -> bool:
        if entry.is_dir:
            return False
        rec = self._records.get(entry.path)
        if rec is None:
            return True
        if not dest_path.exists():
            return True
        if entry.etag and rec.etag == entry.etag and rec.size == entry.size:
            return False
        if not entry.etag and dest_path.stat().st_size == entry.size and rec.size == entry.size:
            return False
        return True

    def mark_synced(
        self,
        *,
        remote_path: str,
        local_path: Path,
        size: int,
        etag: str,
        sha256: str,
    ) -> SyncedFileRecord:
        rec = SyncedFileRecord(
            remote_path=remote_path,
            local_path=str(local_path),
            size=size,
            etag=etag,
            sha256=sha256,
            synced_at=datetime.now(timezone.utc).isoformat(),
        )
        self._records[remote_path] = rec
        self.save()
        return rec


class OpenSSLPSKLocalTunnel:
    """使用系统 openssl s_client 将本机 127.0.0.1 HTTP 连接安全转发到眼镜 TLS-PSK :8443。"""

    def __init__(
        self,
        remote_host: str,
        remote_port: int,
        psk_identity: str,
        psk_key: str,
        *,
        openssl_bin: Optional[str] = None,
    ) -> None:
        self.remote_host = remote_host
        self.remote_port = int(remote_port)
        self.psk_identity = psk_identity
        self.psk_key = psk_key
        self.openssl_bin = openssl_bin or shutil.which("openssl") or "/opt/homebrew/bin/openssl"
        if not os.path.exists(self.openssl_bin):
            raise FileNotFoundError(f"未找到支持 TLS-PSK 的 OpenSSL 可执行文件: {self.openssl_bin}")

        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.local_port: Optional[int] = None

    def start(self) -> int:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        srv.settimeout(0.5)
        self._server_sock = srv
        self.local_port = int(srv.getsockname()[1])
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._serve_loop, daemon=True)
        self._thread.start()
        return self.local_port

    def _serve_loop(self) -> None:
        assert self._server_sock is not None
        while not self._stop_event.is_set():
            try:
                client_sock, _ = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_conn, args=(client_sock,), daemon=True)
            t.start()

    def _handle_conn(self, client_sock: socket.socket) -> None:
        cmd = [
            self.openssl_bin,
            "s_client",
            "-connect",
            f"{self.remote_host}:{self.remote_port}",
            "-psk_identity",
            self.psk_identity,
            "-psk",
            self.psk_key,
            "-quiet",
            "-no_ign_eof",
        ]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        assert proc.stdin is not None and proc.stdout is not None

        def _pump_sock_to_proc() -> None:
            try:
                while True:
                    chunk = client_sock.recv(16384)
                    if not chunk:
                        break
                    proc.stdin.write(chunk)
                    proc.stdin.flush()
            except OSError:
                pass
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    pass

        def _pump_proc_to_sock() -> None:
            try:
                while True:
                    chunk = proc.stdout.read1(16384)  # type: ignore[attr-defined]
                    if not chunk:
                        break
                    client_sock.sendall(chunk)
            except OSError:
                pass
            finally:
                try:
                    client_sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t1 = threading.Thread(target=_pump_sock_to_proc, daemon=True)
        t2 = threading.Thread(target=_pump_proc_to_sock, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        client_sock.close()
        proc.terminate()
        proc.wait(timeout=2)

    def stop(self) -> None:
        self._stop_event.set()
        if self._server_sock is not None:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None


class WebFSReadOnlyClient:
    """严格只读的 genie_webfs WebDAV 客户端。"""

    PROPFIND_BODY = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<D:propfind xmlns:D="DAV:">'
        "<D:prop>"
        "<D:displayname/>"
        "<D:getcontentlength/>"
        "<D:getlastmodified/>"
        "<D:getetag/>"
        "<D:creationdate/>"
        "<D:resourcetype/>"
        "</D:prop>"
        "</D:propfind>"
    )

    def __init__(
        self,
        host: str,
        port: int = 8443,
        *,
        proto: str = "davs",
        root_path: str = "/DCIM/AliCamera",
        psk_identity: str = "",
        psk_key: str = "",
        user_agent: str = "qwen-glasses-lab/0.1",
        timeout: float = 15.0,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.proto = proto.lower()
        self.root_path = "/" + root_path.strip("/") if root_path.strip("/") else "/"
        self.psk_identity = psk_identity
        self.psk_key = psk_key
        self._tunnel: Optional[OpenSSLPSKLocalTunnel] = None

        if transport is not None:
            scheme = "https" if self.proto == "davs" else "http"
            base_url = f"{scheme}://{self.host}:{self.port}"
        elif self.proto == "davs":
            if not (self.psk_identity and self.psk_key):
                raise ValueError("proto='davs' 需要提供由 genWifiPSK 派生的 psk_identity 与 psk_key")
            self._tunnel = OpenSSLPSKLocalTunnel(
                self.host,
                self.port,
                self.psk_identity,
                self.psk_key,
            )
            local_port = self._tunnel.start()
            base_url = f"http://127.0.0.1:{local_port}"
        else:
            base_url = f"http://{self.host}:{self.port}"

        self._client = httpx.Client(
            base_url=base_url,
            headers={"User-Agent": user_agent},
            timeout=timeout,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()
        if self._tunnel is not None:
            self._tunnel.stop()
            self._tunnel = None

    def __enter__(self) -> "WebFSReadOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def request_readonly(
        self,
        method: str,
        remote_path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        content: Optional[bytes] = None,
    ) -> httpx.Response:
        """统一受控只读请求入口；写操作在发包前即抛出 WriteOperationForbiddenError。"""
        checked_method = assert_readonly_http_method(method)
        norm_path = "/" + remote_path.lstrip("/")
        return self._client.request(
            checked_method,
            norm_path,
            headers=headers,
            content=content,
        )

    def propfind(self, remote_path: Optional[str] = None, *, depth: str = "1") -> List[WebFSFileEntry]:
        """发送只读 PROPFIND 列举眼镜端目录结构。"""
        target = remote_path or self.root_path
        resp = self.request_readonly(
            "PROPFIND",
            target,
            headers={
                "Depth": str(depth),
                "Content-Type": "application/xml; charset=utf-8",
            },
            content=self.PROPFIND_BODY.encode("utf-8"),
        )
        if resp.status_code not in (200, 207):
            resp.raise_for_status()
        return parse_propfind_multistatus(resp.content, base_root=target)

    def download_file(
        self,
        remote_path: str,
        dest_path: Path,
    ) -> Tuple[Path, str, int]:
        """以只读 GET 流式下载单个文件并返回 (dest_path, sha256, byte_count)。"""
        checked = assert_readonly_http_method("GET")
        norm_path = "/" + remote_path.lstrip("/")
        dest = Path(dest_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".part")
        hasher = hashlib.sha256()
        total = 0
        with self._client.stream(checked, norm_path) as resp:
            resp.raise_for_status()
            with tmp.open("wb") as fh:
                for chunk in resp.iter_bytes(chunk_size=65536):
                    if not chunk:
                        continue
                    fh.write(chunk)
                    hasher.update(chunk)
                    total += len(chunk)
        os.replace(tmp, dest)
        return dest, hasher.hexdigest(), total

    def sync_incremental(
        self,
        local_dir: Path,
        cursor_store: SyncCursorStore,
        *,
        remote_root: Optional[str] = None,
        depth: str = "2",
    ) -> Dict[str, List[str]]:
        """只读增量同步：仅拉取新增或变更文件，严禁删除眼镜端媒体。"""
        root_target = remote_root or self.root_path
        entries = self.propfind(root_target, depth=depth)
        downloaded: List[str] = []
        skipped: List[str] = []

        root_prefix = root_target.rstrip("/")
        for entry in entries:
            if entry.is_dir:
                continue
            rel = entry.path
            if root_prefix and rel.startswith(root_prefix + "/"):
                rel = rel[len(root_prefix) + 1 :]
            else:
                rel = rel.lstrip("/")
            dest = Path(local_dir) / rel
            if not cursor_store.needs_download(entry, dest):
                skipped.append(entry.path)
                continue
            _, sha256_hex, size_bytes = self.download_file(entry.path, dest)
            cursor_store.mark_synced(
                remote_path=entry.path,
                local_path=dest,
                size=size_bytes,
                etag=entry.etag,
                sha256=sha256_hex,
            )
            downloaded.append(entry.path)

        return {"downloaded": downloaded, "skipped": skipped}
