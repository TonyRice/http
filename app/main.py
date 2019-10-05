# -*- coding: utf-8 -*-

import os

from raven.contrib.tornado import AsyncSentryClient

from tornado import ioloop
from tornado.httpclient import AsyncHTTPClient
from tornado.options import define, options
from tornado.web import Application

from . import handlers
from .Router import Router


define('debug', default=False, help='enable debug')
define('external_port',
       default=int(os.getenv('PORT', '8888')),
       help='Port for external client connections.')
define('internal_port',
       default=int(os.getenv('PORT', '8889')),
       help='Port for internal client connections.')
define('sentry_dsn',
       default=os.getenv('SENTRY_DSN'),
       help='Sentry DSN')
define('routes_file',
       default=os.getenv('ROUTES_FILE',
                         os.path.join(os.path.dirname(__file__),
                                      '../.pickle')),
       help='file location for caching routes')


def make_external_app(router):
    app = Application(
        handlers=[
            (r'/(?P<path>.*)', handlers.ExecHandler)
        ],
        debug=options.debug
    )
    app.router = router
    app.sentry_client = AsyncSentryClient(options.sentry_dsn)
    return app


def make_internal_app(router):
    app = Application(
        handlers=[
            (r'/(?P<action>register|unregister)', handlers.RegisterHandler)
        ],
        debug=options.debug
    )
    app.router = router
    app.sentry_client = AsyncSentryClient(options.sentry_dsn)
    return app


if __name__ == '__main__':
    options.parse_command_line()

    router = Router(options.routes_file)

    AsyncHTTPClient.configure(
        'tornado.curl_httpclient.CurlAsyncHTTPClient', max_clients=60
    )

    external_app = make_external_app(router)
    external_app.listen(options.external_port)

    internal_app = make_internal_app(router)
    internal_app.listen(options.internal_port)

    try:
        ioloop.IOLoop.current().start()
    except KeyboardInterrupt:
        pass
