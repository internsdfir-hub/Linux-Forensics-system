import os
import argparse
import shutil
import urllib.request
import tempfile
import socket

def pack_and_send(target_dir, server_url):
    if not os.path.exists(target_dir):
        print(f"[-] Error: Target directory '{target_dir}' does not exist.")
        return

    print(f"[*] Packing directory: {target_dir}")
    
    temp_dir = tempfile.mkdtemp()
    base_name = os.path.join(temp_dir, "evidence")
    archive_path = ""
    
    try:
        archive_path = shutil.make_archive(base_name, 'zip', target_dir)
        print(f"[+] Successfully packed into {archive_path}")
        
        file_size = os.path.getsize(archive_path)
        print(f"[*] Connecting to {server_url} to send {file_size} bytes...")

        hostname = socket.gethostname()
        filename = f"{hostname}_evidence.zip"

        with open(archive_path, 'rb') as f:
            req = urllib.request.Request(server_url, data=f, method='POST')
            req.add_header('Content-Length', str(file_size))
            req.add_header('X-Filename', filename)
            req.add_header('Content-Type', 'application/zip')

            try:
                with urllib.request.urlopen(req) as response:
                    status_code = response.getcode()
                    resp_body = response.read().decode()
                    if status_code == 200:
                        print(f"[+] Successfully sent evidence to central server. Server says: {resp_body.strip()}")
                    else:
                        print(f"[-] Failed to send. Server returned status {status_code}: {resp_body}")
            except Exception as e:
                print(f"[-] Error connecting to server: {e}")

    finally:
        print("[*] Cleaning up temporary files...")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        print("[*] Done.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Collect, zip, and send forensic data to a central server.")
    parser.add_argument('target_dir', help="Directory to collect and pack")
    parser.add_argument('server_url', help="URL of the central server (e.g. http://192.168.1.10:8000/)")
    
    args = parser.parse_args()
    pack_and_send(args.target_dir, args.server_url)
