import re

FLAG_PATTERN = re.compile(r"[A-Za-z0-9_]{2,20}\{[^}\s]{4,100}\}")


def find_flags(text):
    return FLAG_PATTERN.findall(text)