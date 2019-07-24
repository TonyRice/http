# -*- coding: utf-8 -*-
import logging
from logging import Logger
import os
import re
import pickle
from collections import namedtuple
from tornado.routing import Router, Matcher, RuleRouter, Rule, PathMatches

from . import Config

Resolve = namedtuple('Resolve', ['endpoint', 'paths'])

Route = namedtuple('Route', ['host', 'path', 'endpoint'])

path_re = re.compile(
    r"""
    (?P<wildcard>\*+)              # wildcard ie: /* or /end* or /start/*/end
    |/:(?P<var>[a-zA-Z0-9_]+)  # path variable ie: /user/:id
    """, re.VERBOSE)


def dict_decode_values(_dict):
    """
    {'foo': b'bar'} => {'foo': 'bar'}
    """
    return {
        key: value.decode('utf-8') if value is not None else None
        for key, value in _dict.items()
    }


def build_match_regex(path):
    """
    Parses the provided path and returns the regular expression
    described by the path.
    """

    def match_var_re(var_name):
        return r"/(?P<%s>[A-Za-z0-9-._~()'!*:@,;]+)" % var_name

    # match_wild_re = r"(?:([A-Za-z0-9-._~()'!*:@,;/]+))?"
    match_wild_re = r"(?P<wildcard>[A-Za-z0-9-._~()'!*:@,;/]+)?"

    pos = 0
    end = len(path)
    match_regex_parts = []
    used_names = set()
    wildcard_used = False

    if not path or path[0] is not "/":
        raise ValueError("path must begin with /")

    while pos < end:
        m = path_re.match(path, pos)
        if m is None:
            char = path[pos]
            if char in " :*":
                raise ValueError("invalid path segment contains unexpected character %s." % char)
            if not (pos == end - 1 and char in "/"):
                match_regex_parts.append(char)
            pos = pos + 1
            continue

        g = m.groupdict()
        if g['wildcard']:
            if match_regex_parts and "?P<" in match_regex_parts[-1]:
                raise ValueError("path param segment %s cannot contain wildcard *" % match_regex_parts[-1])
            if wildcard_used:
                raise ValueError("wildcard * used more than once")
            match_regex_parts.append(match_wild_re)
            wildcard_used = True
        else:
            var = g["var"]
            if var.lower() == "wildcard":
                raise ValueError("path variable name :wildcard is reserved")
            if var in used_names:
                raise ValueError("path variable %r used more than once." % var)
            match_regex_parts.append(match_var_re(var))
            used_names.add(var)

        pos = m.end()

    return re.compile(r"^%s/?$" % r"".join(match_regex_parts))


class CustomRouter(Router):
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def find_handler(self, request, **kwargs):
        return Resolve(
            endpoint=self.endpoint,
            paths=dict_decode_values(kwargs.get('path_kwargs', {}))
        )


class MethodMatches(Matcher):
    """Matches requests method"""

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
        self.host = host

    def match(self, request):
        # Truncate the ".storyscriptapp.com" from "foo.asyncyapp.com"
        if request.host[:-(Config.PRIMARY_DOMAIN_LEN + 1)] == self.host:
            return super().match(request)

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
        try:
            match_regex = build_match_regex(path)
        except ValueError:
            self.logger.exception(f'Cannot add route {method} {host} with malformed path {path}')
            return

        self.logger.info(f'Adding route {method} {host} {path} -> {endpoint}')
        self._cache.setdefault(method, dict()) \
            .update({Route(host, path, endpoint): match_regex})
        self._rebuild()

    def unregister(self, host, method, path, endpoint):
        self._cache.get(method, dict()) \
            .pop((host, path, endpoint), None)
        self._rebuild()

    def _rebuild(self):
        """Resolves a uri to the Story and line number to execute."""
        method_rules = []
        for method, routes in self._cache.items():
            rules = [
                Rule(
                    HostAndPathMatches(route.host, match_regex),
                    CustomRouter(route.endpoint)
                ) for route, match_regex in routes.items()
            ]
            # create a new rule by method mapping to many rule by path
            method_rules.append(Rule(MethodMatches(method), RuleRouter(rules)))

        # replace rules
        self.rules = method_rules

        # save route to file
        with open(self.routes_file, 'wb') as file:
            # [TODO] only works for one server
            pickle.dump(self._cache, file)
