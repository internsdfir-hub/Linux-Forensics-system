import os
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer

class ReceiverHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing Content-Length")
                return

            filename = self.headers.get('X-Filename', 'evidence.zip')
            
            # Ensure the uploads directory exists
            os.makedirs("uploads", exist_ok=True)
            filepath = os.path.join("uploads", os.path.basename(filename))

            print(f"[*] Receiving {content_length} bytes. Saving to {filepath}...")
            
            with open(filepath, 'wb') as f:
                remaining = content_length
                chunk_size = 1024 * 1024
                while remaining > 0:
                    read_size = min(chunk_size, remaining)
                    data = self.rfile.read(read_size)
                    if not data:
                        break
                    f.write(data)
                    remaining -= len(data)

            print(f"[+] Successfully saved {filename}.")
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"File received successfully.\n")
        except Exception as e:
            print(f"[-] Error: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode())

def run(port):
    server_address = ('0.0.0.0', port)
    httpd = HTTPServer(server_address, ReceiverHandler)
    print(f"[*] Starting receiver server on port {port}...")
    print("[*] Waiting for evidence...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print("[*] Server stopped.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Central Server for receiving forensic collections.")
    parser.add_argument('--port', type=int, default=8000, help="Port to listen on")
    args = parser.parse_args()
    run(args.port)
