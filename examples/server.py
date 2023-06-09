import os
import sys
from http.server import SimpleHTTPRequestHandler, HTTPServer

class MyHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        # Enable Cross-Origin Resource Sharing with *
        self.send_header('Access-Control-Allow-Origin', '*')
        SimpleHTTPRequestHandler.end_headers(self)

    def do_GET(self):
        example_name = sys.argv[1] if len(sys.argv) > 1 else 'simpleform'
        if self.path == '/':
            self.path = '/' + example_name + '/index.html'
        elif self.path.startswith('/pkg/'):
            self.path = '/' + self.path
        else:
            self.path = '/' + example_name + self.path
        return SimpleHTTPRequestHandler.do_GET(self)

if __name__ == '__main__':
    httpd = HTTPServer(('localhost', 8000), MyHandler)
    print('Server is starting...')
    httpd.serve_forever()

