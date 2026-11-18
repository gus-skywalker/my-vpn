#!/usr/bin/env python3
"""Operator-only: display the bootstrap login in the operator's own terminal.

Do not execute through an assistant tool, record its output or send it in chat.
The bootstrap env-file is not attached to the normal running container.
"""
from pathlib import Path
import sys

if not sys.stdout.isatty():
    raise SystemExit('Run directly in your interactive terminal; output redirection is refused.')
source = Path(__file__).resolve().parent.parent/'state/bootstrap.env'
values = dict(line.split('=', 1) for line in source.read_text().splitlines() if '=' in line)
print('User:', values['INIT_USERNAME'])
print('Password:', values['INIT_PASSWORD'])
