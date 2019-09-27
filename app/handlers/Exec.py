# -*- coding: utf-8 -*-
import json
import typing
import uuid
from collections import namedtuple
from datetime import datetime
from functools import partial
from urllib.parse import urlencode


from raven.contrib.tornado import SentryMixin

import tornado
from tornado.gen import coroutine
from tornado.httpclient import AsyncHTTPClient
from tornado.log import app_log
from tornado.web import RequestHandler

from .FourOhFour import FourOhFour

File = namedtuple('File', ['name', 'body', 'content_type', 'upload_name'])
CLOUD_EVENTS_FILE_KEY = '_ce_payload'


class ExecHandler(SentryMixin, RequestHandler):
    buffer = bytearray()
    response_passthrough = True

    def prepare(self):
        self.set_header('Server', 'Asyncy')

    def resolve_by_uri(self, path):
        """
        A http request to `/*` will resolve to one listener on that channel.
        """
        resolve = self.application.router.find_handler(self.request)

        app_log.info(f'Resolving to {repr(resolve)}')

        if not resolve:
            # exit: path not being followed
            return None, None

        # Do not change the eventType and source.
        # The runtime makes the headers case-insensitive
        # if the eventType is http_request.
        # See
        # https://github.com/storyscript/platform-engine/pull/320/commits/cdb1df7f4fd36783c6b3b1d8ed92f539b672e388
        event = {
            'eventType': 'http_request',
            'cloudEventsVersion': '0.1',
            'source': 'gateway',
            'eventID': str(uuid.uuid4()),
            'eventTime': datetime.utcnow().replace(microsecond=0).isoformat(),
            'contentType': 'application/vnd.omg.object+json',
            'data': {
                'uri': self.request.uri,
                'path': self.request.path,
                'headers': dict(self.request.headers),
            },
        }

        event['data']['query_params'] = {}
        for k, v in self.request.arguments.items():
            event['data']['query_params'][k] = v[0].decode('utf-8')

        if 'application/json' in self.request.headers.get('content-type', ''):
            event['data']['body'] = json.loads(
                self.request.body.decode('utf-8')
            )

        return resolve, event

    @coroutine
    def _handle(self, path):
        resolve, event = self.resolve_by_uri(path)

        if resolve is None and event is None:
            FourOhFour.handle(self)
            self.finish()
            return

        url = resolve.endpoint

        try:
            yield self.execute_request(url, event)
        except:
            import traceback

            traceback.print_exc()
            self.set_status(500, reason='Story execution failed')
            self.write('HTTP 500: Story execution failed\n')

        if not self._finished:
            self.finish()

    @coroutine
    def execute_request(self, url, event):
        """
        If there are any files in the request, then the request made
        to the engine will be multipart/form-data.
        If no files exist, then it'll be a plain old application/json request.
        """
        kwargs = {
            'method': 'POST',
            'url': url,
            'connect_timeout': 10,
            'request_timeout': 60,
            'streaming_callback': self._callback,
            'header_callback': self._on_headers_receive,
        }

        if len(self.request.files) == 0:
            kwargs['body'] = json.dumps(event)
            kwargs['headers'] = {
                'Content-Type': 'application/json; charset=utf-8'
            }
        else:
            boundary = uuid.uuid4().hex
            headers = {
                'Content-Type': f'multipart/form-data; boundary={boundary}'
            }
            files = self._get_request_files()
            self._insert_event_as_file(event, files)
            producer = partial(self.multipart_producer, files, boundary)
            kwargs['headers'] = headers
            kwargs['body_producer'] = producer

        kwargs['headers']['Connection'] = 'keep-alive'
        request = tornado.httpclient.HTTPRequest(**kwargs)
        client = AsyncHTTPClient()
        yield client.fetch(request)

    def _insert_event_as_file(self, event: dict, files: typing.List[File]):
        files.append(
            File(
                name=CLOUD_EVENTS_FILE_KEY,
                body=json.dumps(event).encode('utf-8'),
                content_type='application/json',
                upload_name=CLOUD_EVENTS_FILE_KEY,
            )
        )

    def _get_request_files(self) -> typing.List[File]:
        # File handling:
        # self.request.files looks like this:
        # {"upload_name": [{filename:<>, body:<>, content_type:<>}, {<file>}]}
        all_files = []
        for upload_name in self.request.files:
            for _f in self.request.files[upload_name]:
                all_files.append(
                    File(
                        name=_f['filename'],
                        body=_f['body'],
                        content_type=_f['content_type'],
                        upload_name=upload_name,
                    )
                )
        return all_files

    @coroutine
    def multipart_producer(self, files: typing.List[File], boundary, write):
        """
        Inspired directly from here:
        https://github.com/tornadoweb/tornado/blob/master/demos/file_upload/file_uploader.py
        """
        boundary_bytes = boundary.encode()

        for file in files:
            filename_bytes = file.name.encode()
            upload_name_bytes = file.upload_name.encode()
            buf = (
                (b'--%s\r\n' % boundary_bytes)
                + (
                    b'Content-Disposition: form-data; '
                    b'name="%s"; filename="%s"\r\n'
                    % (upload_name_bytes, filename_bytes)
                )
                + (b'Content-Type: %s\r\n' % file.content_type.encode())
                + b'\r\n'
            )
            yield write(buf)

            # We only write bytes.
            assert isinstance(file.body, bytes)
            yield write(file.body)

            yield write(b'\r\n')

        yield write(b'--%s--\r\n' % (boundary_bytes,))

    def _on_headers_receive(self, header_line: str):
        """
        Checks if a Content-Type header is sent, which indicates if the data
        received is binary. If it's binary, it needs to be streamed to the
        client without the usual command processing logic.
        """
        if header_line.lower().startswith('content-type'):
            parts = header_line.split(':')
            value = parts[1].strip()
            if value.startswith('application/stream+json'):
                self.response_passthrough = False
            else:
                # Since it's not json, push the response to the client as is.
                self.set_header('Content-Type', value)

    def _callback(self, chunk):
        """
        Chunk examples that come from the Engine
            set_status 200
            set_header {"name":"X-Data", "value":"Asyncy"}
            write Hello, world
            ~finish~ will not be passed since it will close the connection
        """

        # If we receive a chunk that beings with the above header,
        # we want to be sure to upgrade the request to response_passthrough
        # ensuring that data gets processed properly. If we send something
        # like set_header, before we send the binary data, it'll break the request
        # without this header.
        if len(chunk) > 12 and chunk[0:12] == b'\n\nBEGIN DATA' and \
                not self.response_passthrough:

            self.response_passthrough = True
            chunk = chunk[12:]

        if self.response_passthrough:
            self.write(chunk)
            return

        # Read `chunk` byte by byte and add it to the buffer.
        # When a byte is \n, then parse everything in the buffer as string,
        # and interpret the resulting JSON string.

        instructions = []
        for b in chunk:
            if b == 0x0A:  # 0x0A is an ASCII/UTF-8 new line.
                instructions.append(self.buffer.decode('utf-8'))
                self.buffer.clear()
            else:
                self.buffer.append(b)

        # If we have any new instructions, execute them.
        for ins in instructions:
            ins = json.loads(ins)
            command = ins['command']
            if command == 'write':
                if ins['data'].get('content') is None:
                    self.write('null')
                else:
                    self.write(ins['data']['content'])
                if ins['data'].get('flush'):
                    self.flush()
            elif command == 'set_status':
                self.set_status(ins['data']['code'])
            elif command == 'set_cookie':
                # name, value, domain, expires, path, expires_days, secure
                if ins['data'].pop('secure', False):
                    self.set_cookie(**ins['data'])
                else:
                    self.set_secure_cookie(**ins['data'])
            elif command == 'clear_cookie':
                # name, domain, path
                self.clear_cookie(**ins['data'])
            elif command == 'clear_all_cookie':
                # domain, path
                self.clear_cookie(**ins['data'])
            elif command == 'set_header':
                self.set_header(ins['data']['key'], ins['data']['value'])
            elif command == 'flush':
                self.flush()
            elif command == 'redirect':
                redir_url = ins['data']['url']
                params = ins['data'].get('query')
                if isinstance(params, dict):
                    # Convert boolean True/False to true/false as strings,
                    # because of Python's silly-ness.
                    self.handle_boolean_values(params)
                    query_string = urlencode(params)
                    if '?' in redir_url:
                        redir_url = f'{redir_url}&{query_string}'
                    else:
                        redir_url = f'{redir_url}?{query_string}'
                self.redirect(redir_url)
            elif command == 'finish':
                # can we close quicker here?
                break
            else:
                raise NotImplementedError(f'{command} is not implemented!')

    def handle_boolean_values(self, params: dict):
        for k, v in params.items():
            if isinstance(v, bool):
                if v:
                    params[k] = 'true'
                else:
                    params[k] = 'false'

    @coroutine
    def head(self, path):
        yield self._handle(path)

    @coroutine
    def get(self, path):
        yield self._handle(path)

    @coroutine
    def post(self, path):
        yield self._handle(path)

    @coroutine
    def delete(self, path):
        yield self._handle(path)

    @coroutine
    def patch(self, path):
        yield self._handle(path)

    @coroutine
    def put(self, path):
        yield self._handle(path)

    def options(self, path):
        """
        Returns the allowed options for this endpoint
        """
        self.set_header('Allow', 'GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS')
        # [FUTURE] http://zacstewart.com/2012/04/14/http-options-method.html
        self.finish()
