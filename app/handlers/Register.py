# -*- coding: utf-8 -*-

from json import loads

from raven.contrib.tornado import SentryMixin

from tornado.web import RequestHandler


class RegisterHandler(SentryMixin, RequestHandler):
    def post(self, action):
        """
        (un)Register a route
        """
        req = loads(self.request.body)

        # Note: The following is not the same as .get('method', 'get').
        method = req['data'].get('method') or 'get'

        if self.request.path == '/register':
            self.application.router.register(
                req['data']['host'],
                method,
                req['data']['path'],
                req['endpoint'])
            self.set_status(201)
        else:
            self.application.router.unregister(
                req['data']['host'],
                method,
                req['data']['path'],
                req['endpoint'])
            self.set_status(204)
