# -*- coding: utf-8 -*-
import logging
import os
import pickle
import re
from collections import namedtuple

from tornado.routing import Matcher, \
    PathMatches, Router, Rule, RuleRouter

from . import Config

Resolve = namedtuple('Resolve', ['endpoint', 'paths'])

Route = namedtuple('Route', ['host', 'path', 'endpoint'])


path_re = re.compile(
    r"""
    (\*+)              # wildcard ie: /* or /end* or /start/*/end
    |/:([a-zA-Z0-9_]+)
    |/([a-zA-Z0-9_]+)# path variable ie: /user/:id
    """,
    re.VERBOSE,
)

# this is used to match "simple paths, and attempt to
# match without regex to speed up processing
path_matcher = re.compile('^([A-Za-z0-9-._~()\'!@,;_/]+)$')

wild_matcher = re.compile(
    "^(?P<wildcard>[A-Za-z0-9-._~()\\'!*:@,;_/]+)?(?P<endpath>/)?$"
)

match_wild_re = r'(?P<wildcard>[A-Za-z0-9-._~()\'!*:@,;_/]+)?'


def match_var_re(var_name):
    return r'/(?P<%s>[A-Za-z0-9-._~()\'!*:@,;]+)?' % var_name


def build_route_matcher(path):
    """
    Parses the provided path and returns the regular expression
    described by the path.
    """

    if path is None:
        return None

    match_regex_parts = []
    used_names = set()

    if not path or (path[0] != '/' and path[0] != '*'):
        raise ValueError('path must begin with / or *')

    # If we are attempting to match a simple path, let's go
    # ahead and return the path. This will tell the matcher
    # to avoid regex matching if the path is the same.

    path_exact = path_matcher.match(path)
    if path_exact is not None and \
            path_exact[0] is path:
        return path

    if path == '/*' or path == '*':
        match_regex_parts.append(match_wild_re)
    else:
        count = 0
        for m in path_re.findall(path):
            count = count + 1
            if m[0] is not '':
                # wildcard

                if match_wild_re in match_regex_parts:
                    raise ValueError('wildcard * used more than once')

                match_regex_parts.append(match_wild_re)
            elif m[1] is not '':
                # path variables

                var = m[1]

                if var.lower() == 'wildcard':
                    raise ValueError(
                        'path variable name :wildcard is reserved'
                    )

                if var in used_names:
                    raise ValueError(
                        'path variable %r used more than once.' % var
                    )
                match_regex_parts.append(match_var_re(var))
                used_names.add(var)
            elif m[2] is not '':
                # regular path
                match_regex_parts.append(f'/{m[2].replace("/", "")}')

    # we utilize this so we do not cause any errors
    match_regex_parts.append(r'(?P<endpath>/)?')

    return re.compile(r'^%s$' % r''.join(match_regex_parts))


def dict_decode_values(_dict):
    """
    {'foo': b'bar', 'boo': None} => {'foo': 'bar'}
    """

    values = {}
    for key, value in _dict.items():
        if value is not None:
            values[key] = value.decode()

    return values


class CustomRouter(Router):
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def find_handler(self, request, **kwargs):
        return Resolve(
            endpoint=self.endpoint,
            paths=dict_decode_values(kwargs.get('path_kwargs', {}))
        )


class MethodMatches(Matcher):
    """
    Matches requests method
    """

    def __init__(self, method):
        self.method = method.upper()

    def match(self, request):
        if request.method == self.method:
            return {}
        else:
            return None


class HostAndPathMatches(PathMatches):

    def __init__(self, host, path_pattern):
        super().__init__(path_pattern)
        self.path_pattern = path_pattern
        self.host = host
        self.match_cache = {}

    def match(self, request):

        # Truncate the ".storyscriptapp.com" from "foo.asyncyapp.com" and
        # ignore ports for local debugging
        host = request.host.split(':')[0]

        if host[:-(Config.PRIMARY_DOMAIN_LEN + 1)] == self.host.split(':')[0]:

            # we know it's a wildcard match,
            # so let's just go ahead and speed things up
            if self.path_pattern is wild_matcher:
                return {
                    'path_args': [],
                    'path_kwargs': {
                        'wildcard': request.path.encode(),
                        'endpath': None
                    }
                }

            request_key = (self.host + request.path)

            # below we override the super, and implement
            # our own map based cache. This helps us
            # save a few ms from caching
            if request_key in self.match_cache:
                return self.match_cache[request_key]

            # This avoids the need for regex when the
            # path_pattern is exactly the same as the
            # request path.
            safe_path = request.path.split('?')[0]
            safe_pattern = str(self.path_pattern)

            if safe_path in safe_pattern:
                if safe_path == safe_pattern:
                    return {}
                elif safe_pattern.endswith('/') and \
                        safe_pattern.startswith(safe_path) and \
                        not safe_path.endswith('/') and \
                        safe_pattern == (safe_path + '/'):
                    self.match_cache[request_key] = {}

                    return {}

            value = super().match(request)

            # we don't store anything for wildcard matched
            # routes. We do this so we don't fill up the
            # memory via malicious requests
            if '?P<wildcard>' not in str(self.path_pattern):
                self.match_cache[request_key] = value

            return value

        return None


class Router(RuleRouter):

    logger = logging.getLogger('router')

    def __init__(self, routes_file):
        super().__init__()
        self.routes_file = routes_file
        self.rules = []
        self._cache = {}

        if os.path.exists(routes_file):
            # Server restarted, load the cache of routes
            with open(routes_file, 'rb') as file:
                self._cache = pickle.load(file)
            self._rebuild()

    def register(self, host, method, path, endpoint):
        self.logger.info(f'Adding route {method} {host} {path} -> {endpoint}')
        try:
            route_matcher = build_route_matcher(path)
        except ValueError:
            self.logger.exception(
                f'Cannot add route {method} {host} with malformed path {path}'
            )
            return
        self._cache.setdefault(method, {}).update(
            {Route(host, path, endpoint): route_matcher}
        )
        self._rebuild()

    def unregister(self, host, method, path, endpoint):
        self._cache.get(method, {}).pop((host, path, endpoint), None)
        self._rebuild()

    def _rebuild(self):
        """
        Resolves a uri to the Story and line number to execute.
        """
        method_rules = []
        for method, routes in self._cache.items():
            rules = []
            for route, match_regex in routes.items():
                rules.append(Rule(
                    HostAndPathMatches(route.host, match_regex),
                    CustomRouter(route.endpoint),
                ))
            # create a new rule by method mapping to many rule by path
            method_rules.append(Rule(MethodMatches(method), RuleRouter(rules)))

        # replace rules
        self.rules = method_rules

        # save route to file
        with open(self.routes_file, 'wb') as file:
            # [TODO] only works for one server
            pickle.dump(self._cache, file)
