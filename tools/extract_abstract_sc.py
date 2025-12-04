#!/usr/bin/env python3
import re
import requests
import json
from html.parser import HTMLParser


class SyscallParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.abstract_syscalls = {}
        self.current_data = []
        self.in_italic = False
        self.in_font = False

    def handle_starttag(self, tag, attrs):
        if tag == "i":
            self.in_italic = True
        elif tag == "font":
            for attr, value in attrs:
                if attr == "color" and value == "#111111":
                    self.in_font = True

    def handle_endtag(self, tag):
        if tag == "i":
            self.in_italic = False
            if self.current_data:
                self.parse_definition("".join(self.current_data))
                self.current_data = []
        elif tag == "font":
            self.in_font = False

    def handle_data(self, data):
        if self.in_italic and self.in_font:
            self.current_data.append(data)

    def parse_definition(self, text):
        # Match: name(params) - description = { body }
        match = re.match(
            r"([a-zA-Z_0-9]+)\s*\((.*?)\)\s*-\s*(.*?)\s*=\s*\{(.*)\}", text, re.DOTALL
        )

        if not match:
            return

        name = match.group(1).strip()
        params = match.group(2).strip()
        description = match.group(3).strip()
        body = match.group(4).strip()

        # Parse syscalls from body
        syscalls = []
        for line in body.split("\n"):
            line = line.strip().rstrip(",;")
            if not line or line == "}":
                continue

            # Check for condition
            if "|" in line:
                parts = line.split("|", 1)
                syscall = parts[0].strip()
                condition = parts[1].strip()
            else:
                syscall = line
                condition = None

            # Extract base syscall name
            syscall_name_match = re.match(r"([a-zA-Z_0-9]+)", syscall)
            if syscall_name_match:
                entry = {"call": syscall, "base_name": syscall_name_match.group(1)}
                if condition:
                    entry["condition"] = condition
                syscalls.append(entry)

        self.abstract_syscalls[name] = {
            "parameters": params,
            "description": description,
            "implementations": syscalls,
        }


# Usage
url = "https://www.seclab.cs.sunysb.edu/sekar/papers/classifbody.htm"
resp = requests.get(url, timeout=15)
resp.raise_for_status()
html_content = resp.text

parser = SyscallParser()
parser.feed(html_content)

# Save as JSON
with open("abstract_syscalls.json", "w") as f:
    json.dump(parser.abstract_syscalls, f, indent=2)

print(f"Extracted {len(parser.abstract_syscalls)} abstract syscalls")
