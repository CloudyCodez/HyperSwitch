import argparse
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hyperswitch.metadata import APP_NAME, DEBUG_APP_NAME

def copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def copy_tree(source: Path, destination: Path) -> None:
    if not source.exists():
        return
    shutil.copytree(source, destination, dirs_exist_ok=True)


def build_release_tree(root: Path, dist_dir: Path) -> None:
    copy_file(dist_dir / f"{APP_NAME}.exe", root / f"{APP_NAME}.exe")
    copy_file(dist_dir / f"{DEBUG_APP_NAME}.exe", root / "debug" / f"{DEBUG_APP_NAME}.exe")

    for source_name, target_name in (
        ("hyperv_switch.py", "source/hyperv_switch.py"),
        ("requirements.txt", "source/requirements.txt"),
        ("build.ps1", "source/build.ps1"),
        ("generate_icon.py", "source/generate_icon.py"),
        ("hyperswitch.ico", "assets/hyperswitch.ico"),
        ("hyperswitch.png", "assets/hyperswitch.png"),
        ("hyperswitch-source.png", "assets/hyperswitch-source.png"),
        ("chibi-cloud-watermark.png", "assets/chibi-cloud-watermark.png"),
    ):
        copy_file(Path(source_name), root / target_name)
    copy_file(Path("README.md"), root / "docs" / "README.md")
    copy_file(Path("LICENSE"), root / "docs" / "LICENSE.txt")
    copy_tree(Path("docs"), root / "docs")


def main() -> None:
    parser = argparse.ArgumentParser(description="Package a HyperSwitch release bundle.")
    parser.add_argument("--version", required=True, help="Release version, with or without the leading v.")
    parser.add_argument("--dist-dir", default="dist", help="Directory containing built executables.")
    parser.add_argument("--output-dir", default="out", help="Directory for packaged release artifacts.")
    args = parser.parse_args()

    version = args.version if args.version.startswith("v") else f"v{args.version}"
    dist_dir = Path(args.dist_dir)
    output_dir = Path(args.output_dir)
    bundle_root = output_dir / f"{APP_NAME}-{version}"
    zip_base = output_dir / f"{APP_NAME}-{version}-portable"

    output_dir.mkdir(parents=True, exist_ok=True)
    if bundle_root.exists():
        shutil.rmtree(bundle_root)

    build_release_tree(bundle_root, dist_dir)

    zip_path = shutil.make_archive(str(zip_base), "zip", root_dir=output_dir, base_dir=bundle_root.name)
    print(bundle_root)
    print(zip_path)


if __name__ == "__main__":
    main()
