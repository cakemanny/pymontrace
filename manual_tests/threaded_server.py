from http import HTTPStatus
import http.server
import os
import socketserver
import threading
import signal


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    pass


class MyHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        self.respond_simple(HTTPStatus.OK, 'howdy\n')

    def respond_simple(
        self, status, message, content_type='text/plain; charset=utf-8',
        charset='utf-8'
    ):
        response_bytes = message.encode(charset)
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)


def main():
    host, port = '127.0.0.1', int(os.getenv('PORT', 8000))
    httpd = ThreadedHTTPServer((host, port), MyHandler)

    def signal_handler(signum, _frame):
        # http.server requires that shutdown is called on a separate thread.
        # There are two ways of running our server
        #
        #   (1) we run the server on the main thread and start a second thread in
        #   the handler to call shutdown.
        #
        #   (2) we run the server on a second thread and wait for it to join. The
        #   signal is handled on the main thread and thus is able to call shutdown
        #   without causeing a deadlock.
        #
        # We'll go with first option as it will make the process simpler when
        # observing with a debugger. That is only having 1 thread until it wants to
        # die.
        signame = signal.Signals(signum).name
        print(f'badapp: received {signame} ({signum}), shutting down...')
        t = threading.Thread(target=lambda httpd: httpd.shutdown(), args=[httpd])
        t.start()
        # we don't join, as we must return to the interrupted httpd code for it
        # to shutdown.
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    print(f'listening at http://{host}:{port}/')
    httpd.serve_forever()


if __name__ == '__main__':
    main()
