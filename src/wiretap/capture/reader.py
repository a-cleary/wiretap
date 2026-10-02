from collections.abc import Iterator
from pathlib import Path
from typing import Protocol, Any


class PacketReader(Protocol):
    def read(self) -> Iterator[Any]:
        """Yield packets from a capture."""
        ...


class PcapReader:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def read(self) -> Iterator[Any]:
        from scapy.utils import PcapReader as ScapyPcapReader

        with ScapyPcapReader(str(self.path)) as reader:
            for packet in reader:
                yield packet