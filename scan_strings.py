import base64
import binascii
import codecs
import io
import re
import zipfile
from pathlib import Path

from flag_finder import find_flags

FOLDER = "ZIP Files"
MIN_LENGTH = 4
SHOW_ALL_UNDER = 3000
MAX_SHOWN = 80

STRING_PATTERN = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LENGTH)
BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]{12,}={0,2}$")
HEX_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2}){8,}$")

KEYWORDS = ("pass", "user", "login", "auth", "secret", "token",
            "key", "flag", "admin", "cookie", "ftp", "telnet", "://",
            "retr", "stor", "list", "150 ", "226 ", "230 ")
SIGNATURES = [
    (b"\xd4\xc3\xb2\xa1", "pcap capture", "network forensics"),
    (b"\xa1\xb2\xc3\xd4", "pcap capture", "network forensics"),
    (b"\x0a\x0d\x0d\x0a", "pcapng capture", "network forensics"),
    (b"\x7fELF", "Linux program", "reverse engineering"),
    (b"MZ", "Windows program", "reverse engineering"),
    (b"dex\n", "Android code", "reverse engineering"),
    (b"\x89PNG", "PNG image", "steganography / forensics"),
    (b"\xff\xd8\xff", "JPEG image", "steganography / forensics"),
    (b"%PDF", "PDF document", "forensics"),
    (b"PK\x03\x04", "zip-based archive", "nested archive"),
]


def identify(data):
    for magic, kind, category in SIGNATURES:
        if data.startswith(magic):
            return kind, category
    return "unknown or text", "misc"


def extract_strings(data):
    found = STRING_PATTERN.findall(data)
    return [s.decode("ascii") for s in found]


def decode_attempts(token):
    results = []
    if BASE64_PATTERN.match(token):
        try:
            text = base64.b64decode(token, validate=True).decode("ascii")
            if text.isprintable():
                results.append(("base64", text))
        except (binascii.Error, UnicodeDecodeError):
            pass
    if HEX_PATTERN.match(token):
        try:
            text = bytes.fromhex(token).decode("ascii")
            if text.isprintable():
                results.append(("hex", text))
        except (ValueError, UnicodeDecodeError):
            pass
    rot = codecs.decode(token, "rot13")
    if find_flags(rot) and not find_flags(token):
        results.append(("rot13", rot))
    return results


def is_interesting(s):
    lowered = s.lower()
    return any(word in lowered for word in KEYWORDS) or bool(find_flags(s))


def scan_data(name, data, label):
    kind, category = identify(data)
    print(label + name, "|", kind, "|", category)

    strings = extract_strings(data)
    flags = find_flags("\n".join(strings))

    decoded_hits = []
    for s in strings:
        for token in s.split():
            for method, text in decode_attempts(token):
                decoded_hits.append((method, token, text))
                flags += find_flags(text)

    print("   ", len(strings), "strings,", len(set(flags)), "flags")
    for flag in dict.fromkeys(flags):
        print("    FLAG FOUND:", flag)

    for method, token, text in decoded_hits[:20]:
        print("    DECODED (" + method + "):", token[:30], "->", text[:80])

    if len(data) < SHOW_ALL_UNDER:
        shown = strings
    else:
        shown = [s for s in strings if is_interesting(s)][:MAX_SHOWN]
        print("    (big file: showing only interesting strings)")
    for s in shown:
        print("      |", s)


def scan_archive(z, label=""):
    for entry in z.infolist():
        if entry.is_dir() or entry.filename.startswith("__MACOSX"):
            continue
        if entry.flag_bits & 1:
            print(label + entry.filename, "-> LOCKED, skipped")
            continue

        data = z.read(entry)

        if entry.filename.lower().endswith((".zip", ".apk", ".jar")):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as inner:
                    scan_archive(inner, label + entry.filename + " > ")
                continue
            except zipfile.BadZipFile:
                pass

        scan_data(entry.filename, data, label)


count = 0
for zip_path in Path(FOLDER).rglob("*.zip"):
    count = count + 1
    print("=" * 40)
    print("Zip", count, ":", zip_path.name)
    try:
        with zipfile.ZipFile(zip_path) as z:
            scan_archive(z)
    except zipfile.BadZipFile:
        print("ERROR: not a valid zip file")

print("=" * 40)
print("Total zips scanned:", count)