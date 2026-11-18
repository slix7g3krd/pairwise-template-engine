import pytest

from security.template_engine import (
    render,
    check_template,
    safe_include,
    escape,
    cache_key
)


def test_plain():
    assert render('Hi {{ name }}', {'name': 'World'}, set()) == 'Hi World'

def test_escape():
    assert escape('<') == '&lt;'

def test_dunder():
    assert check_template('{{ x.__class__ }}') is False

def test_attr_filter():
    assert check_template('{{ x|attr("y") }}') is False

def test_filter():
    assert render('{{ x|upper }}', {'x': 'a'}, {'upper'}) == 'A'

def test_unknown_filter():
    assert check_template('{{ x|evil }}') is False

def test_include_traversal():
    assert safe_include('../etc/passwd', '/root') is None

def test_include_ok():
    assert safe_include('a.html', '/root') == '/root/a.html'

def test_cache_tenant():
    assert cache_key('t1', 'x') != cache_key('t2', 'x')

def test_script():
    assert check_template('<script>alert(1)</script>') is False

def test_macro():
    assert check_template('{% macro x() %}') is False

def test_eval():
    assert check_template('{{ eval("1") }}') is False

def test_empty():
    assert render('', {}, set()) == ''

def test_autoescape():
    assert render('{{ x }}', {'x': '<b>'}, set()) == '&lt;b&gt;'

def test_nested():
    assert check_template('{{ a|upper|escape }}') is True
