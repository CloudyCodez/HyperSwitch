from __future__ import annotations

from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "hyperswitch-source.png"
PNG_OUT = ROOT / "hyperswitch.png"
ICO_OUT = ROOT / "hyperswitch.ico"
SIZES = [16, 24, 32, 48, 64, 128, 256]


def main() -> None:
    if not SOURCE.exists():
        raise FileNotFoundError(f"Missing icon source: {SOURCE}")

    with Image.open(SOURCE) as src:
        rgba = src.convert("RGBA")
        rgba.save(PNG_OUT)
        rgba.save(ICO_OUT, format="ICO", sizes=[(size, size) for size in SIZES])


if __name__ == "__main__":
    main()
