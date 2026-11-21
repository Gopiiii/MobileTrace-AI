"""Pure-Python JPEG EXIF (APP1 / TIFF IFD) metadata extractor."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any


_EXIF_TAGS = {
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x0131: "Software",
    0x0132: "DateTime",
    0x8769: "ExifIFDPointer",
    0x8825: "GPSInfoIFDPointer",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x9010: "OffsetTime",
    0x9011: "OffsetTimeOriginal",
}

_GPS_TAGS = {
    0x0001: "GPSLatitudeRef",
    0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef",
    0x0004: "GPSLongitude",
    0x001D: "GPSDateStamp",
}

_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def _read_value(data: bytes, tiff_start: int, endian: str, fmt_type: int, count: int, value_offset_bytes: bytes) -> Any:
    unit = _TYPE_SIZES.get(fmt_type)
    if not unit:
        return None
    total = unit * count
    if total <= 4:
        raw = value_offset_bytes[:total]
    else:
        offset = struct.unpack(endian + "I", value_offset_bytes)[0]
        start = tiff_start + offset
        if start < 0 or start + total > len(data):
            return None
        raw = data[start : start + total]

    if fmt_type == 2:
        return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
    if fmt_type == 3:
        vals = struct.unpack(endian + "H" * count, raw)
        return vals[0] if count == 1 else list(vals)
    if fmt_type == 4:
        vals = struct.unpack(endian + "I" * count, raw)
        return vals[0] if count == 1 else list(vals)
    if fmt_type in (5, 10):
        fmt_char = "I" if fmt_type == 5 else "i"
        out: list[float] = []
        for idx in range(count):
            num, den = struct.unpack(endian + fmt_char + fmt_char, raw[idx * 8 : (idx + 1) * 8])
            out.append(num / den if den != 0 else 0.0)
        return out[0] if count == 1 else out
    return None


def _parse_ifd(data: bytes, tiff_start: int, ifd_offset: int, endian: str, tag_map: dict[int, str]) -> dict[str, Any]:
    pos = tiff_start + ifd_offset
    if pos + 2 > len(data):
        return {}
    num_entries = struct.unpack(endian + "H", data[pos : pos + 2])[0]
    pos += 2
    parsed: dict[str, Any] = {}
    for _ in range(num_entries):
        if pos + 12 > len(data):
            break
        tag, fmt_type, count = struct.unpack(endian + "HHI", data[pos : pos + 8])
        val_bytes = data[pos + 8 : pos + 12]
        pos += 12
        name = tag_map.get(tag)
        if name:
            val = _read_value(data, tiff_start, endian, fmt_type, count, val_bytes)
            if val is not None:
                parsed[name] = val
    return parsed


def _dms_to_decimal(dms: Any, ref: str | None) -> float | None:
    if not isinstance(dms, list) or len(dms) != 3:
        return None
    deg, mins, secs = dms
    dec = float(deg) + float(mins) / 60.0 + float(secs) / 3600.0
    if ref in ("S", "W"):
        dec = -dec
    return round(dec, 6)


def extract_jpeg_exif(file_path: Path) -> dict[str, Any]:
    """Extract basic camera, timestamp, and GPS EXIF tags from a JPEG file."""
    try:
        with file_path.open("rb") as f:
            header = f.read(2)
            if header != b"\xff\xd8":
                return {}
            while True:
                marker_bytes = f.read(2)
                if len(marker_bytes) < 2:
                    break
                if marker_bytes[0] != 0xFF:
                    break
                marker = marker_bytes[1]
                if marker in (0xDA, 0xD9):  # SOS or EOI
                    break
                seg_len_bytes = f.read(2)
                if len(seg_len_bytes) < 2:
                    break
                seg_len = struct.unpack(">H", seg_len_bytes)[0]
                if seg_len < 2:
                    break
                payload = f.read(seg_len - 2)
                if marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
                    tiff_data = payload[6:]
                    if len(tiff_data) < 8:
                        return {}
                    endian = "<" if tiff_data[:2] == b"II" else ">" if tiff_data[:2] == b"MM" else ""
                    if not endian:
                        return {}
                    first_ifd = struct.unpack(endian + "I", tiff_data[4:8])[0]
                    ifd0 = _parse_ifd(tiff_data, 0, first_ifd, endian, _EXIF_TAGS)
                    result = {k: v for k, v in ifd0.items() if not k.endswith("Pointer")}
                    if isinstance(ifd0.get("ExifIFDPointer"), int):
                        exif_sub = _parse_ifd(tiff_data, 0, ifd0["ExifIFDPointer"], endian, _EXIF_TAGS)
                        result.update({k: v for k, v in exif_sub.items() if not k.endswith("Pointer")})
                    if isinstance(ifd0.get("GPSInfoIFDPointer"), int):
                        gps_sub = _parse_ifd(tiff_data, 0, ifd0["GPSInfoIFDPointer"], endian, _GPS_TAGS)
                        lat = _dms_to_decimal(gps_sub.get("GPSLatitude"), gps_sub.get("GPSLatitudeRef"))
                        lon = _dms_to_decimal(gps_sub.get("GPSLongitude"), gps_sub.get("GPSLongitudeRef"))
                        if lat is not None and lon is not None:
                            result["gps_latitude"] = lat
                            result["gps_longitude"] = lon
                        if gps_sub.get("GPSDateStamp"):
                            result["gps_date"] = gps_sub["GPSDateStamp"]
                    return result
    except Exception:
        return {}
    return {}
