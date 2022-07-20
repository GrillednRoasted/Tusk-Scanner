#!/bin/env python3

import pytest
import project as p 

def test_check_email():
    assert p.check_email("invalid email") == False
    assert p.check_email("valid@email.com") == True
    assert p.check_email(" ") == False
    assert p.check_email("fake email") == False
    assert p.check_email(1235) == False

def test_toint():
    assert p.toint("35") == 35
    assert p.toint(35) == 35
    assert p.toint([1,2,3]) == 0
    assert p.toint(1.2) == 0

def test_reverse_dns():
    assert p.reverse_dns("172.253.122.99") != ""
    assert p.reverse_dns("172.253.122.147") != ""
    assert p.reverse_dns("www.google.com") == ""
    assert p.reverse_dns("test") == ""
    assert p.reverse_dns(10) == ""
