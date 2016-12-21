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
"""
Built-in predicates used as core building blocks to build predicates
"""

import ast
import abc
from functools import reduce
from .predicate import Predicate


class BuiltinPredicate(Predicate, metaclass=abc.ABCMeta):  # pylint: disable=abstract-method
    """
    Build in predicate abstract class
    """
    pass


class NaryPredicate(BuiltinPredicate, metaclass=abc.ABCMeta):  # pylint: disable=abstract-method
    """
    N-ary predicate abstract class
    """
    def __init__(self, children):
        super().__init__()
        self._children = children

    def _str(self, operator):
        ret = ""
        for child in self._children:
            if len(ret) > 0:
                ret += " %s " % operator
            ret += str(child)

        if len(self._children) > 1:
            ret = "(" + ret + ")"

        return ret

    @staticmethod
    def _create(tree, cls, nodes_from, flow):
        """
        Instantiate N-ary predicate cls

        :param tree: node from which should be predicate instantiated
        :type tree: List
        :param cls: class of type NaryPredicate
        :param nodes_from: nodes that are used in described edge
        :param flow: flow to which predicate belongs to
        :type flow: Flow
        :return: instance of cls
        """
        if not isinstance(tree, list):
            raise ValueError("Nary logical operators expect list of children")
        children = []
        for child in tree:
            children.append(Predicate.construct(child, nodes_from, flow))
        return cls(children)

    def predicates_used(self):
        """
        :return: used predicates by children
        """
        return reduce(lambda x, y: x + y.predicates_used(), self._children, [])

    def check(self):
        """
        Check predicate for consistency
        """
        for child in self._children:
            child.check()


class UnaryPredicate(BuiltinPredicate, metaclass=abc.ABCMeta):  # pylint: disable=abstract-method
    """
    Unary predicate abstract class
    """
    def __init__(self, child):
        super().__init__()
        self._child = child

    @staticmethod
    def _create(tree, cls, nodes_from, flow):
        """
        Instantiate N-ary predicate cls

        :param tree: node from which should be predicate instantiated
        :type tree: List
        :param cls: class of type NaryPredicate
        :param nodes_from: nodes that are used in described edge
        :param flow: flow to which predicate belongs to
        :return: instance of cls
        """
        if isinstance(tree, list):
            raise ValueError("Unary logical operators expect one child")
        return cls(Predicate.construct(tree, nodes_from, flow))

    def predicates_used(self):
        """
        :return: used predicates by children
        """
        return self._child.predicates_used()

    def check(self):
        """
        Check predicate for consistency
        """
        self._child.check()


class AndPredicate(NaryPredicate):
    """
    And predicate representation
    """
    def __str__(self):
        return "(" + reduce(lambda x, y: str(x) + ' and ' + str(y), self._children) + ")"

    def ast(self):
        """
        :return: AST of describing all children predicates
        """
        return ast.BoolOp(ast.And(), [ast.Expr(value=x.ast()) for x in self._children])

    @staticmethod
    def create(tree, nodes_from, flow):
        """
        Create And predicate

        :param tree: node from which should be predicate instantiated
        :type tree: List
        :param nodes_from: nodes that are used in described edge
        :param flow: flow to which predicate belongs to
        :type flow: Flow
        :return: instance of cls
        """
        return NaryPredicate._create(tree, AndPredicate, nodes_from, flow)


class OrPredicate(NaryPredicate):
    """
    And predicate representation
    """
    def __str__(self):
        return "(" + reduce(lambda x, y: str(x) + ' or ' + str(y), self._children) + ")"

    def ast(self):
        """
        :return: AST of describing all children predicates
        """
        return ast.BoolOp(ast.Or(), [ast.Expr(value=x.ast()) for x in self._children])

    @staticmethod
    def create(tree, nodes_from, flow):
        """
        Create Or predicate

        :param tree: node from which should be predicate instantiated
        :type tree: List
        :param nodes_from: nodes that are used in described edge
        :param flow: flow to which predicate belongs to
        :type flow: Flow
        :return: instance of cls
        """
        return NaryPredicate._create(tree, OrPredicate, nodes_from, flow)


class NotPredicate(UnaryPredicate):
    """
    Unary or predicate representation
    """
    def __str__(self):
        return "(not %s)" % str(self._child)

    def ast(self):
        """
        :return: AST of describing all children predicates
        """
        return ast.UnaryOp(ast.Not(), ast.Expr(value=self._child.ast()))

    @staticmethod
    def create(tree, nodes_from, flow):
        """
        Create Or predicate

        :param tree: node from which should be predicate instantiated
        :type tree: List
        :param nodes_from: nodes that are used in described edge
        :param flow: flow to which predicate belongs to
        :type flow: Flow
        :return: instance of cls
        """
        return UnaryPredicate._create(tree, NotPredicate, nodes_from, flow)


class AlwaysTruePredicate(BuiltinPredicate):
    """
    Predicate used if condition in config file is omitted
    """
    def __init__(self, flow):
        super().__init__()
        self.flow = flow

    def __str__(self):
        return "True"

    def predicates_used(self):
        return []

    def check(self):
        """
        Check predicate for consistency
        """
        pass

    def ast(self):
        """
        :return: AST
        """
        # We should return:
        #   return ast.NameConstant(value=True)
        # but it does not work with codegen
        return ast.Name(id='True', ctx=ast.Load())

    @staticmethod
    def create(tree, nodes_from, flow):
        return AlwaysTruePredicate(flow)
