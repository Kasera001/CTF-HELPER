import re
import zipfile
from pathlib import Path

ZIP_PATH = Path("ZIP Files") / "Cleartext Catch.zip"

TEXT_RUN = re.compile(rb"[\x20-\x7e]{3,}")
FTP_START = re.compile(
    r"(USER |PASS |RETR |STOR |LIST|NLST|CWD |PWD|TYPE |PASV|SIZE |QUIT|[1-5]\d\d [A-Za-z])"
)

with zipfile.ZipFile(ZIP_PATH) as z:
    for entry in z.infolist():
        if not entry.filename.lower().endswith((".pcap", ".pcapng")):
            continue
        data = z.read(entry)
        print("File:", entry.filename)
        for run in TEXT_RUN.findall(data):
            text = run.decode("ascii")
            match = FTP_START.search(text)
            if match:
                print(text[match.start():])