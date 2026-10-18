"""Loader for the CSIC 2010 HTTP dataset (same source and format as the SentinelShield project).
Vendored here, trimmed to what this project needs, so DetectorMutation has no path dependency on
a sibling repo.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlsplit

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "raw" / "csic2010"
FILES = {
    "normalTrafficTraining.txt": ("normal", "train"),
    "normalTrafficTest.txt": ("normal", "test"),
    "anomalousTrafficTest.txt": ("anomalous", "test"),
}

_START = re.compile(r"^(GET|POST|PUT|HEAD|OPTIONS|TRACE|DELETE|CONNECT|PATCH)\s+(\S+)\s+HTTP/\d\.\d\s*$")


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    label: int = 0  # 1 = attack
    source_file: str = ""

    @property
    def path(self) -> str:
        return urlsplit(self.url).path

    @property
    def query(self) -> str:
        return urlsplit(self.url).query


def parse_requests(text: str, label: int = 0, source_file: str = "") -> List[HttpRequest]:
    lines = [line.rstrip("\r") for line in text.split("\n")]
    requests: List[HttpRequest] = []
    i, n = 0, len(lines)
    while i < n:
        match = _START.match(lines[i])
        if not match:
            i += 1
            continue
        method, url = match.group(1), match.group(2)
        i += 1
        headers: Dict[str, str] = {}
        while i < n and lines[i].strip() != "":
            key, sep, value = lines[i].partition(":")
            if sep:
                headers[key.strip().lower()] = value.strip()
            i += 1
        i += 1
        body = ""
        try:
            content_length = int(headers.get("content-length", "0"))
        except ValueError:
            content_length = 0
        if content_length > 0:
            body_lines = []
            while i < n and lines[i].strip() != "" and not _START.match(lines[i]):
                body_lines.append(lines[i])
                i += 1
            body = "\n".join(body_lines)
        requests.append(HttpRequest(method=method, url=url, headers=headers, body=body, label=label, source_file=source_file))
    return requests


def load_csic(data_dir: Path = DATA_DIR) -> List[HttpRequest]:
    out: List[HttpRequest] = []
    for name, (kind, _split) in FILES.items():
        path = data_dir / name
        if not path.exists():
            raise FileNotFoundError(
                f"{path} is missing. Copy the three CSIC 2010 traffic files into {data_dir} "
                "(same files used by the SentinelShield project)."
            )
        text = path.read_bytes().decode("latin-1")
        out.extend(parse_requests(text, label=1 if kind == "anomalous" else 0, source_file=name))
    return out
