"""User-interface assets.

Every HTML template, stylesheet and script LFA renders lives here as a real
file rather than inside a Python f-string. Python prepares data; these files
decide how it looks. Assets are inlined at render time so a report remains a
single self-contained document with no external fetches.
"""
