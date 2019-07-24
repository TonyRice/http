# -*- coding: utf-8 -*-
from unittest import mock
from pytest import mark, raises

from app.Router import build_match_regex, HostAndPathMatches, dict_decode_values


def assert_match(match, e):
    if type(e) is not dict or type(match) is not dict:
        assert match == e
    elif match == {}:
        assert match == e
    else:
        comp_val = dict_decode_values(match['path_kwargs'])
        assert set(comp_val.keys()) == set(e.keys())
        for key in comp_val.keys():
            assert comp_val[key] == e[key]

@mark.parametrize('path, e1, e2, e3, e4', [
    ('/source/page/50/', {}, None, None, None),
    ('/source', None, None, None, None),
    ('/some/other/path', None, None, None, None),

    ('/:a', None, {"a": "random"}, None, None),
    ('/source/page/:c/', {"c": "50"}, None, None, None),
    ('/:a/page/:c', {"a": "source", "c": "50"}, None, None, {"a": "r1", "c": "r2"}),
    ('/:a/:b/:c', {"a": "source", "b": "page", "c": "50"}, None, None, {"a": "r1", "b": "page", "c": "r2"}),
    ('/:a/something/:c', None, None, None, None),
    ('/:a/:b/:c/:d', None, None, None, None),

    ('/*', {'wildcard': 'source/page/50'}, {'wildcard': 'random/'}, {'wildcard': None}, {'wildcard': 'r1/page/r2'}),
    ('/source/pa*', {'wildcard': 'ge/50'}, None, None, None),
    ('****/', {'wildcard': '/source/page/50'}, {'wildcard': '/random/'}, {'wildcard': '/'}, {'wildcard': '/r1/page/r2'}),
    ('/nomatch*', None, None, None, None),
    ('/source/pag*', {'wildcard': 'e/50'}, None, None, None),

    ('/:from/*', {"from": "source", "wildcard": "page/50"}, {"from": "random", "wildcard": None},
     None, {"from": "r1", "wildcard": "page/r2"}),
    ('/:from/*/:id', {"from": "source", "wildcard": "page", "id": "50"}, None, None,
     {"from": "r1", "wildcard": "page", "id": "r2"}),
    ('/*/:c', {'wildcard': 'source/page', 'c': '50'}, None,
     None, {'wildcard': 'r1/page', 'c': 'r2'}),
    ('*/:b/50/', {'wildcard': '/source', 'b': 'page'}, None,
     None, None),
])
def test_path_matching(path, e1, e2, e3, e4):
    match_params = build_match_regex(path)
    matcher = HostAndPathMatches("foo.asyncyapp.com", match_params)

    req1 = mock.Mock(path="/source/page/50", host="foo.asyncyapp.com.storyscriptapp.com")
    match = matcher.match(req1)
    assert_match(match, e1)

    req2 = mock.Mock(path="/random/", host="foo.asyncyapp.com.storyscriptapp.com")
    match = matcher.match(req2)
    assert_match(match, e2)

    req3 = mock.Mock(path="/", host="foo.asyncyapp.com.storyscriptapp.com")
    match = matcher.match(req3)
    assert_match(match, e3)

    req4 = mock.Mock(path="/r1/page/r2", host="foo.asyncyapp.com.storyscriptapp.com")
    match = matcher.match(req4)
    assert_match(match, e4)

@mark.parametrize('path', [
    '/:from/*/:id/*/:var',
    '*/*',
    '/:from*/',
    '/:a/:b/:a',
    '/:wildcard',
    'path_wild_no_forward_slash',
    ':path_var_with_no_forward_slash',
    '',
    ])
def test_malformed_path_raises(path):
    with raises(ValueError):
        build_match_regex(path)
