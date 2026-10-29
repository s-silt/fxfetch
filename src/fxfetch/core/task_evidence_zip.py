"""Bounded structural preflight for task evidence ZIP archives."""

from __future__ import annotations

import os
import struct
import time
from pathlib import Path
from typing import BinaryIO

from .task_evidence_schema import EvidenceError

MAX_TASK_ZIP_DIRECTORY_BYTES = 8 * 1024 * 1024
MAX_ZIP_TAIL_BYTES = 22 + 65535
_EOCD = struct.Struct("<4s4H2LH")
_ZIP64_LOCATOR = struct.Struct("<4sIQI")
_ZIP64_END = struct.Struct("<4sQ2H2I4Q")
_CENTRAL_HEADER_BYTES = 46
_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_ZIP64_END_SIGNATURE = b"PK\x06\x06"
_CENTRAL_HEADER_SIGNATURE = b"PK\x01\x02"


def preflight_task_zip(
    path: Path,
    *,
    max_entries: int,
    deadline: float,
    max_directory_bytes: int = MAX_TASK_ZIP_DIRECTORY_BYTES,
) -> None:
    """Validate ZIP structure without constructing ``zipfile.ZipFile``."""
    _check_deadline(deadline)
    try:
        with path.open("rb") as archive:
            archive.seek(0, os.SEEK_END)
            file_size = archive.tell()
            tail_size = min(file_size, MAX_ZIP_TAIL_BYTES)
            archive.seek(file_size - tail_size)
            tail = archive.read(tail_size)
            if len(tail) != tail_size:
                raise EvidenceError("task_evidence_zip_end_record_invalid")
            eocd_offset, classic = _find_eocd(tail, file_size)
            (
                _signature,
                disk_number,
                central_disk,
                entries_on_disk,
                entries_total,
                central_size,
                central_offset,
                _comment_length,
            ) = classic

            locator_offset = eocd_offset - _ZIP64_LOCATOR.size
            locator = (
                _read_exact(archive, locator_offset, _ZIP64_LOCATOR.size)
                if locator_offset >= 0
                else b""
            )
            has_zip64_locator = locator[:4] == _ZIP64_LOCATOR_SIGNATURE
            if has_zip64_locator:
                (
                    _locator_signature,
                    locator_disk,
                    zip64_offset,
                    total_disks,
                ) = _ZIP64_LOCATOR.unpack(locator)
                if locator_disk != 0 or total_disks != 1:
                    raise EvidenceError("task_evidence_zip64_invalid")
                if zip64_offset + _ZIP64_END.size != locator_offset:
                    raise EvidenceError("task_evidence_zip64_invalid")
                zip64_end = _read_exact(archive, zip64_offset, _ZIP64_END.size)
                (
                    end_signature,
                    record_size,
                    _version_made,
                    _version_needed,
                    zip64_disk,
                    zip64_central_disk,
                    zip64_entries_on_disk,
                    zip64_entries_total,
                    zip64_central_size,
                    zip64_central_offset,
                ) = _ZIP64_END.unpack(zip64_end)
                if end_signature != _ZIP64_END_SIGNATURE or record_size != 44:
                    raise EvidenceError("task_evidence_zip64_invalid")
                if (
                    zip64_disk != 0
                    or zip64_central_disk != 0
                    or zip64_entries_on_disk != zip64_entries_total
                ):
                    raise EvidenceError("task_evidence_zip64_invalid")
                _match_classic(
                    disk_number,
                    central_disk,
                    entries_on_disk,
                    entries_total,
                    central_size,
                    central_offset,
                    (
                        zip64_disk,
                        zip64_central_disk,
                        zip64_entries_on_disk,
                        zip64_entries_total,
                        zip64_central_size,
                        zip64_central_offset,
                    ),
                )
                directory_end = zip64_offset
                directory_count = zip64_entries_total
                directory_size = zip64_central_size
                directory_offset = zip64_central_offset
            else:
                if any(
                    (
                        disk_number == 0xFFFF,
                        central_disk == 0xFFFF,
                        entries_on_disk == 0xFFFF,
                        entries_total == 0xFFFF,
                        central_size == 0xFFFFFFFF,
                        central_offset == 0xFFFFFFFF,
                    )
                ):
                    raise EvidenceError("task_evidence_zip64_invalid")
                if (
                    disk_number != 0
                    or central_disk != 0
                    or entries_on_disk != entries_total
                ):
                    raise EvidenceError("task_evidence_zip_end_record_invalid")
                directory_end = eocd_offset
                directory_count = entries_total
                directory_size = central_size
                directory_offset = central_offset

            if directory_count <= 0 or directory_count > max_entries:
                raise EvidenceError("task_evidence_entry_count_invalid")
            if directory_size > max_directory_bytes:
                raise EvidenceError("task_evidence_zip_directory_too_large")
            if (
                directory_offset > file_size
                or directory_size > file_size - directory_offset
                or directory_offset + directory_size != directory_end
            ):
                raise EvidenceError("task_evidence_zip_directory_invalid")

            position = directory_offset
            for _ in range(directory_count):
                _check_deadline(deadline)
                if position + _CENTRAL_HEADER_BYTES > directory_end:
                    raise EvidenceError("task_evidence_zip_directory_invalid")
                header = _read_exact(archive, position, _CENTRAL_HEADER_BYTES)
                if header[:4] != _CENTRAL_HEADER_SIGNATURE:
                    raise EvidenceError("task_evidence_zip_directory_invalid")
                filename_size, extra_size, comment_size = struct.unpack_from(
                    "<3H", header, 28
                )
                variable_size = filename_size + extra_size + comment_size
                next_position = position + _CENTRAL_HEADER_BYTES + variable_size
                if next_position > directory_end:
                    raise EvidenceError("task_evidence_zip_directory_invalid")
                archive.seek(next_position)
                position = next_position
                _check_deadline(deadline)
            if position != directory_end:
                raise EvidenceError("task_evidence_zip_directory_invalid")
    except EvidenceError:
        raise
    except struct.error as error:
        raise EvidenceError("task_evidence_zip_structure_invalid") from error


def _find_eocd(
    tail: bytes, file_size: int
) -> tuple[int, tuple[bytes, int, int, int, int, int, int, int]]:
    candidates: list[tuple[int, tuple[bytes, int, int, int, int, int, int, int]]] = []
    end = len(tail)
    while end:
        position = tail.rfind(_EOCD_SIGNATURE, 0, end)
        if position < 0:
            break
        if position + _EOCD.size <= len(tail):
            values = _EOCD.unpack_from(tail, position)
            if position + _EOCD.size + values[-1] == len(tail):
                candidates.append((file_size - len(tail) + position, values))
        end = position
    if len(candidates) != 1:
        raise EvidenceError("task_evidence_zip_end_record_invalid")
    return candidates[0]


def _match_classic(
    disk_number: int,
    central_disk: int,
    entries_on_disk: int,
    entries_total: int,
    central_size: int,
    central_offset: int,
    zip64: tuple[int, int, int, int, int, int],
) -> None:
    for classic, expanded, sentinel in (
        (disk_number, zip64[0], 0xFFFF),
        (central_disk, zip64[1], 0xFFFF),
        (entries_on_disk, zip64[2], 0xFFFF),
        (entries_total, zip64[3], 0xFFFF),
        (central_size, zip64[4], 0xFFFFFFFF),
        (central_offset, zip64[5], 0xFFFFFFFF),
    ):
        if classic != sentinel and classic != expanded:
            raise EvidenceError("task_evidence_zip64_invalid")


def _read_exact(archive: BinaryIO, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0:
        raise EvidenceError("task_evidence_zip_structure_invalid")
    archive.seek(offset)
    value = archive.read(size)
    if len(value) != size:
        raise EvidenceError("task_evidence_zip_structure_invalid")
    return value


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise EvidenceError("task_evidence_seal_timeout")
