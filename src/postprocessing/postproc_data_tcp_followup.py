#!/usr/bin/env python3
"""Collapse TCP packet rows, merge follow-ups, and annotate every initial response."""
from postproc_common import main

if __name__ == "__main__":
    main("tcp")
