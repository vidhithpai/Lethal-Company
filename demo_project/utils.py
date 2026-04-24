import os
import subprocess


def read_file(filename):
    # VULNERABLE: no path validation — path traversal
    with open(filename, "r") as f:
        return f.read()


def write_file(filename, content):
    # VULNERABLE: arbitrary write
    with open(filename, "w") as f:
        f.write(content)


def run_shell(command):
    # VULNERABLE: shell injection
    os.system(command)


def sanitize_input(data):
    # SANITIZER: basic cleaning
    return str(data).replace("'", "").replace(";", "").replace("|", "").strip()


def validate_filename(filename):
    # SANITIZER: filename validation
    clean = os.path.basename(filename)
    if ".." in clean or clean.startswith("/"):
        raise ValueError("Invalid filename")
    return clean


def encode_output(data):
    # SANITIZER: HTML encoding
    return str(data).replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;")
