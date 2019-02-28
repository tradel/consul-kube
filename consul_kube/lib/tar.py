from io import BytesIO
from tarfile import TarFile, TarInfo


class TarInMemory:

    def __init__(self) -> None:
        super().__init__()
        self._buf = BytesIO()
        self._tar = TarFile(fileobj=self._buf, mode="w")

    def add(self, filename: str, content: bytes) -> None:
        buf = BytesIO(content)
        info = TarInfo(filename)
        info.size = len(content)
        self._tar.addfile(info, buf)

    def close(self) -> bytes:
        self._tar.close()
        final = self._buf.getbuffer().tobytes()
        self._buf.close()
        return final