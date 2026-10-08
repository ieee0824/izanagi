from http.server import BaseHTTPRequestHandler,HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'ok')
    def log_message(self,*args):pass
HTTPServer(('127.0.0.1',19090),Handler).serve_forever()
