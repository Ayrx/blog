import http.server

import os

import os.path


PORT = 8080


class BlogRequestHandler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, *args, directory=None, **kwargs):
        super().__init__(*args, **kwargs)

    def translate_path(self, path):
        path = http.server.SimpleHTTPRequestHandler.translate_path(self, path)
        relpath = os.path.relpath(path, os.getcwd())
        fullpath = os.path.join(self.server.base_path, relpath)
        return fullpath

    def do_GET(self):
        possible_name = self.path.strip("/") + ".html"
        if self.path == "/":
            # default routing, instead of "index.html"
            self.path = "index.html"
        elif os.path.isfile(self.translate_path(possible_name)):
            # extensionless page serving
            self.path = possible_name

        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def end_headers(self):
        self.send_my_headers()
        http.server.SimpleHTTPRequestHandler.end_headers(self)

    def send_my_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")


Handler = BlogRequestHandler


def serve_site():
    with http.server.HTTPServer(("", PORT), Handler) as httpd:
        print("serving at port", PORT)
        httpd.base_path = os.path.join(os.getcwd(), "output")
        httpd.serve_forever()
