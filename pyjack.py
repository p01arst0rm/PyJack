#!/usr/bin/env python3
import sys
import argparse
import socket
import threading
from urllib.request import urlopen
from http.server import HTTPServer, BaseHTTPRequestHandler


HTTP_HEAD = {
    "Content-Type": "text/html; charset=utf-8",
    "X-Custom-Header": "Clickjack-Test"}


# Helper Functions
# ----------------------------

def help():
    print("PyJack - HTTP Clickjack Tester")

def is_vulnerable(url):
    try:
        http_head = urlopen(url).info()
        if not "X-Frame-Options" in http_head: return True
    except: return False

def get_free_tcp_port():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('', 0))
    addr, port = tcp.getsockname()
    tcp.close()
    return port

def mk_recv(url) -> str:
    return """
    <!doctype html>
    <html>
    <head>
        <title>PyJack - Clickjack Tester</title>
        <style>
            body {{background:#640fd3;color: #eeeeee;display: block;}}
            h1,p {{margin-top: 20px;margin-left: 40px;line-height:0.5em;}}
            iframe {{width:1080px;height:720px;margin:auto;display:block;}}
        </style>
        <script>
            src="{0}"
            function setWindowOrigin()
            {{
                document.getElementById("window-origin").innerHTML=window.origin;
                console.log(window.origin)
            }}
            function setIFrameSrc()
            {{
                document.getElementById('iframe-src').innerHTML=src;
                document.getElementById('iframe').src=src;
                console.log(src)
            }}
            function main() 
            {{
                setWindowOrigin();
                setIFrameSrc();

            }}
        </script>
    </head>
        <body onload="main()">
            <h1>Framable Response Check</h1>
            <p>window.origin: <b id="window-origin"></b> -- IFrame Target: <b id="iframe-src"></b></p>
            <iframe id="iframe" src=""></iframe>
        </body>
    </html>
    """.format(url)


# Optional PyQt5 WebCamera
# ----------------------------

def mk_webcamera():
    try:
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtCore import Qt, QUrl, QTimer
        from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineSettings
    except ImportError:
        return None

    class WebCamera(QWebEngineView):
            def __init__(self, app: QApplication):
                super().__init__()
                self.app = app
                self.output_file = None

                # Hidden view (no on-screen window)
                self.setAttribute(Qt.WA_DontShowOnScreen)
                self.page().settings().setAttribute(QWebEngineSettings.ShowScrollBars, False)

            def _take_screenshot(self):
                if self.output_file:
                    print(f"saving file: {self.output_file}")
                    self.grab().save(self.output_file, b"PNG")
                self.app.quit()

            def _on_load(self, ok: bool):
                if not ok:
                    print("Failed to load page for screenshot.")
                    self.app.quit()
                    return

                # Resize to full contents, then wait a beat and screenshot
                size = self.page().contentsSize().toSize()
                self.resize(size)
                QTimer.singleShot(800, self._take_screenshot)

            def capture(self, url: str, output_file: str):
                self.output_file = output_file
                self.loadFinished.connect(self._on_load)
                self.load(QUrl(url))
                self.show()

    return WebCamera




def mk_srv(target: str):
    class ClickjackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                html = mk_recv(target).encode("utf-8")
                self.send_response(200)

                for header, value in HTTP_HEAD.items():
                    self.send_header(header, value)
                
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
            except Exception as e:
                print("unexpected error{}".format(e))
    return ClickjackHandler

def parse_args():
    p = argparse.ArgumentParser(description="Mini HTTP server for ClickJack Testing.")
    p.add_argument("--target", required=True, type=str, help="Specify target url")
    p.add_argument("--host", default="127.0.0.1", help="specify Host Address (Optional)")
    p.add_argument("--port", type=int, default=get_free_tcp_port(), help="Specify Bind port (Optional)")
    p.add_argument("--screencap", action=argparse.BooleanOptionalAction, default=False, help="Screenshot test page, then exit")
    args = p.parse_args()

    # Sanity checks
    if "http" not in args.target:
        print('[!] looks like your target is missing a schema!')
        print('[?] did you mean: http://{}'.format(args.target))
        sys.exit()

    return args

def main():
    args = parse_args()
    target = args.target
    host,port = args.host, args.port
    handler_cls = mk_srv(target)
    httpd = HTTPServer((host, port), handler_cls)
    host_url = "http://{}:{}".format(host,port)


    print('\n----------------------------')
    print('[+] Checking if target is vulnerable...')

    if is_vulnerable(target): print('[!] Target is vulnerable!')
    else:
        print('[x] Target is not vulnerable. Exiting.')
        sys.exit()

    # Start server in background so we can run Qt in main thread
    print('\n----------------------------')
    print('[+] Serving ClickJack test: {}'.format(host_url))
    print("[+] Iframe Target: {}".format(target))

    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()


    # Optional screencap
    if args.screencap:
        print('\n----------------------------')
        print("[+] Attempting to screenshot ClickJack page...\n")

        WebCamera = mk_webcamera()
        if WebCamera is None:
            print("[!] Skipping screenshot: PyQt5 not installed.")
            print("[?] Install on Debian/Ubuntu:")
            print("    sudo apt install python3-pyqt5 python3-pyqt5.qtwebengine")
        else:
            from PyQt5.QtWidgets import QApplication

            app = QApplication(sys.argv)
            cam = WebCamera(app)
            cam.capture(host_url, "ClickJack.png")
            app.exec_()

            # Clean shutdown after screencap
            print('\n----------------------------\n')
            print( "[!] Success!! closing down.")
            httpd.shutdown()
            httpd.server_close()
            sys.exit()

    print('\n----------------------------\n')
    print("[!] Serving ClickJack. CTRL+C to exit.")
    # If not screencapping, just keep serving
    try:
        t.join()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()


    

if __name__ == "__main__":
    main()
