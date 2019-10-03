# -*- coding: utf-8 -*-
from unittest import mock
from pytest import mark, raises

from app.Router import build_route_matcher, HostAndPathMatches, dict_decode_values


@mark.parametrize('path, req_path, expected', [
    ('/some/other/path', '/source/page/50', None),

    ('/source/page/50/', '/source/page/50/', {}),
    ('/source/page/50/', '/source/page/50', {}),
    ('/source/page/50', '/source/page/50/', None),

    ('/source', '/source/page/50', None),

    ('/source/page/50/', '/source/page/50', {}),
    ('/source/page/:c/', '/source/page/50', {'c': '50'}),

    ('/:a', '/random/', {'a': 'random', 'endpath': '/'}),
    ('/:a', '/random', {'a': 'random'}),
    ('/:a/', '/random/', {'a': 'random', 'endpath': '/'}),
    ('/:a/', '/random', {'a': 'random'}),

    ('/:a/page/:c', '/source/page/50', {'a': 'source', 'c': '50'}),
    ('/:a/page/:c', '/r1/page/r2', {'a': 'r1', 'c': 'r2'}),
    ('/:a/:b/:c', '/r1/page/50', {'a': 'r1', 'b': 'page', 'c': '50'}),
    ('/:a/:b/:c', '/r1/page/r2', {'a': 'r1', 'b': 'page', 'c': 'r2'}),
    ('/:a/something/:c', '/r1/page/r2', None),
    ('/:a/:b/:c/:d', '/r1/page/r2', None),

    ('/source/page/50/*', '/source/page/50/hello/world', {'wildcard': '/hello/world'}),
    ('/*', '/source/page/50', {'wildcard': '/source/page/50'}),
    ('/*/', '/source/page/50', {'wildcard': '/source/page/50'}),
    ('/*/', '/source/page/50/', {'wildcard': '/source/page/50/'}),
    ('/*', '/', {'wildcard': '/'}),
    ('****/', '/source/page/50', {'wildcard': '/source/page/50'}),
    ('****/', '/source/***/page/50', {'wildcard': '/source/***/page/50'}),
    ('****/', '/**/***/page/50', {'wildcard': '/**/***/page/50'}),


    ('/nomatch*', '/', None),

    ('/source/pa*', '/source/page/50', {'wildcard': 'ge/50'}),
    ('/source/pag*', '/source/page/50', {'wildcard': 'e/50'}),

    ('/:from*/', '/source/page/50', {'from': 'source', 'wildcard': '/page/50'}),
    ('/:from*/', '/source/page/50/', {'from': 'source', 'wildcard': '/page/50/'}),
    ('/:from/*', '/source/page/50', {'from': 'source', 'wildcard': '/page/50'}),
    ('/:from/*/:id', '/source/page/50', {'from': 'source', 'wildcard': '/page', 'id': '50'}),
    ('/*/:c', '/source/page/50', {'wildcard': '/source/page', 'c': '50'}),
    ('*/:b/50/', '/source/page/50', {'wildcard': '/source', 'b': 'page'}),
])
def test_path_matching(path, req_path, expected):
    match_params = build_route_matcher(path)

    matcher = HostAndPathMatches('foo.asyncyapp.com', match_params)

    req = mock.Mock(path=req_path, host='foo.asyncyapp.com.storyscriptapp.com')
    match = matcher.match(req)

    if type(expected) is not dict or type(match) is not dict:
        assert match == expected
    elif match == {}:
        assert match == expected
    else:
        comp_val = dict_decode_values(match['path_kwargs'])
        assert set(comp_val.keys()) == set(expected.keys())
        for key in comp_val.keys():
            assert comp_val[key] == expected[key]


@mark.parametrize('path', [
    '/:from/*/:id/*/:var',
    '/:a/:b/:a',
    '/:wildcard',
    'path_wild_no_forward_slash',
    ':path_var_with_no_forward_slash',
    '',
    ])
def test_malformed_path_raises(path):
    with raises(ValueError):
        build_route_matcher(path)
