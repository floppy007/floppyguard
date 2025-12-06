#!/usr/bin/env python3

import argparse
import http.server
import os
import socketserver


class SpaRequestHandler(http.server.SimpleHTTPRequestHandler):
	def __init__(self, *args, directory=None, **kwargs):
		self._spa_directory = directory or os.getcwd()
		super().__init__(*args, directory=self._spa_directory, **kwargs)

	def send_head(self):
		candidate = self.translate_path(self.path)
		if self._is_real_path(candidate):
			return super().send_head()

		original_path = self.path
		try:
			self.path = "/index.html"
			return super().send_head()
		finally:
			self.path = original_path

	def _is_real_path(self, candidate):
		if os.path.isdir(candidate):
			index_html = os.path.join(candidate, "index.html")
			return os.path.exists(index_html)
		return os.path.exists(candidate)


def parse_args():
	parser = argparse.ArgumentParser(description="Serve a SPA with index.html fallback.")
	parser.add_argument("--host", default="127.0.0.1")
	parser.add_argument("--port", type=int, default=4173)
	parser.add_argument("--root", required=True)
	return parser.parse_args()


def main():
	args = parse_args()
	root = os.path.abspath(args.root)

	class ReusableTCPServer(socketserver.TCPServer):
		allow_reuse_address = True

	with ReusableTCPServer(
		(args.host, args.port),
		lambda *handler_args, **handler_kwargs: SpaRequestHandler(
			*handler_args,
			directory=root,
			**handler_kwargs,
		),
	) as httpd:
		httpd.serve_forever()


if __name__ == "__main__":
	main()
