from __future__ import annotations

import shutil
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Iterator

DEFAULT_MAX_FILES = 1000
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024
DEFAULT_MAX_TOTAL_SIZE = 50 * 1024 * 1024


def is_zip_input(path: str | Path) -> bool:
    candidate = Path(path)
    if candidate.suffix.lower() != ".zip":
        return False
    return zipfile.is_zipfile(candidate)


def _is_unsafe_member_path(name: str) -> bool:
    if name.startswith(("/", "\\")):
        return True
    parts = PurePosixPath(name).parts
    return ".." in parts


def _extract_zip(
    zip_path: Path,
    dest_dir: Path,
    *,
    max_files: int,
    max_file_size: int,
    max_total_size: int,
) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path) as zf:
        file_count = 0
        total_size = 0
        entries = zf.infolist()

        for info in entries:
            if _is_unsafe_member_path(info.filename):
                raise ValueError(f"Unsafe path in zip entry: {info.filename}")
            if info.is_dir():
                continue
            file_count += 1
            if file_count > max_files:
                raise ValueError("Zip file exceeds maximum file count limit.")
            if info.file_size > max_file_size:
                raise ValueError(f"Zip entry exceeds maximum file size: {info.filename}")
            total_size += info.file_size
            if total_size > max_total_size:
                raise ValueError("Zip file exceeds maximum total size limit.")

        for info in entries:
            target = dest_dir / info.filename
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as source, open(target, "wb") as sink:
                shutil.copyfileobj(source, sink)


@contextmanager
def extract_zip_to_tempdir(
    zip_path: str | Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="mcp_scanner_zip_") as tmp_dir:
        dest = Path(tmp_dir)
        _extract_zip(
            Path(zip_path),
            dest,
            max_files=max_files,
            max_file_size=max_file_size,
            max_total_size=max_total_size,
        )
        yield dest
