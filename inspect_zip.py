# zip inspector
# zip has comments that has clues like flags and password hints
import io
import zipfile
from pathlib import Path

FOLDER = "ZIP Files"      # must match your real folder name exactly
MAX_DEPTH = 3              # how many zips-inside-zips to open
MAX_NESTED_SIZE = 50 * 1024 * 1024
NESTED_TYPES = (".zip", ".apk", ".jar")


def inspect_archive(z, depth=0):
    indent = "    " * depth

    comment = z.comment.decode(errors="replace")
    print(indent + "Comment:", comment if comment else "(none)")

    for entry in z.infolist():
        if entry.filename.startswith("__MACOSX") or entry.is_dir():
            continue

        locked = entry.flag_bits & 1
        print(indent + entry.filename, entry.file_size, "LOCKED" if locked else "")

        is_nested = entry.filename.lower().endswith(NESTED_TYPES)
        if is_nested and not locked and depth < MAX_DEPTH:
            if entry.file_size > MAX_NESTED_SIZE:
                print(indent + "  >> too big to open")
                continue
            try:
                inner_bytes = io.BytesIO(z.read(entry))
                with zipfile.ZipFile(inner_bytes) as inner:
                    print(indent + "  >> inside", entry.filename + ":")
                    inspect_archive(inner, depth + 1)
            except zipfile.BadZipFile:
                print(indent + "  >> not a valid archive")


def inspect_zip(zip_path):
    print("=" * 40)
    print("Zip:", zip_path.name)
    try:
        with zipfile.ZipFile(zip_path) as z:
            inspect_archive(z)
    except zipfile.BadZipFile:
        print("ERROR: not a valid zip file, or it is corrupted")
    except Exception as error:
        print("ERROR: something unexpected happened:", error)


folder = Path(FOLDER)
print("Looking in:", folder.resolve())

if not folder.exists():
    print("ERROR: that folder does not exist. Folders next to this script:")
    for item in Path(".").iterdir():
        if item.is_dir() and not item.name.startswith("."):
            print("  ", item.name)
else:
    count = 0
    for zip_path in folder.rglob("*.zip"):
        inspect_zip(zip_path)
        count = count + 1

    print("=" * 40)
    if count == 0:
        print("No .zip files found in that folder or its subfolders.")
    else:
        print("Zips processed:", count)


    