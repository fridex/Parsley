#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ####################################################################
# Copyright (C) 2016  Fridolin Pokorny, fpokorny@redhat.com
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# ####################################################################
"""Selinonlib library helpers"""

import os
import sys
import ast
import json
from contextlib import contextmanager
from dill.source import getsource


def dict2strkwargs(dict_):
    """
    Convert a dictionary into arguments to a string representation that can be used as arguments to a function
    """
    ret = ""
    for key, value in dict_.items():
        if len(ret) > 0:
            ret += ", "
        ret += "%s=%s" % (key, expr2str(value))
    return ret


def expr2str(expr):
    """
    Convert a Python expression into a Python code
    """
    if isinstance(expr, dict):
        return str(expr)
    elif isinstance(expr, list):
        # s/'['foo']['bar']'/['foo']['bar']/ (get rid of leading ')
        return "%s" % expr
    elif isinstance(expr, str):
        return "'%s'" % expr
    else:
        # some build in type such as bool/int/...
        return "%s" % str(expr)


def keylist2str(keylist):
    """
    Convert keylist to a string representation

    :param keylist: keylist to be converted
    :type keylist: list
    :return: string representation
    :rtype: str
    """
    return "".join(map(lambda x: "['" + str(x) + "']", keylist))


@contextmanager
def pushd(new_dir):
    """
    Traverse directory tree in push/pop manner

    :param new_dir: new directory to cd to
    :type new_dir: str
    """
    prev_dir = os.getcwd()
    os.chdir(new_dir)
    try:
        yield
    finally:
        os.chdir(prev_dir)


def dict2json(dict_, pretty=True):
    """
    Convert dict to json (string)

    :param dict_: dictionary to be converted
    :param pretty: if True, nice formatting will be used
    :type pretty: bool
    :return: formatted dict in json
    :rtype: str
    """
    if pretty is True:
        return json.dumps(dict_, sort_keys=True, separators=(',', ': '), indent=2)
    else:
        return json.dumps(dict_)


def get_function_arguments(function):
    """
    Get arguments of function

    :param function: function to parse arguments
    :return: list of arguments that predicate function expects
    """
    ret = []

    func_source = getsource(function)
    func_ast = ast.parse(func_source)
    call = func_ast.body[0]

    for arg in call.args.args:
        # Python2 and Python3 have different AST representations for arg, this can be removed since we support
        # only python3
        if sys.version_info[0] == 2:
            ret.append(arg.id)
        else:
            ret.append(arg.arg)

    return ret
