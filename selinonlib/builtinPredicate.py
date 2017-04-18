#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ######################################################################
# Copyright (C) 2016-2017  Fridolin Pokorny, fridolin.pokorny@gmail.com
# This file is part of Selinon project.
# ######################################################################
"""
Built-in predicates used as core building blocks to build predicates
"""

import abc
import ast
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
    def _create(tree, cls, nodes_from, flow, can_inspect_results):
        """
        Instantiate N-ary predicate cls

        :param tree: node from which should be predicate instantiated
        :type tree: List
        :param cls: class of type NaryPredicate
        :param nodes_from: nodes that are used in described edge
        :param flow: flow to which predicate belongs to
        :type flow: Flow
        :param can_inspect_results: True if predicates in the condition can query task result
        :type can_inspect_results: bool
        :return: instance of cls
        """
        if not isinstance(tree, list):
            raise ValueError("Nary logical operators expect list of children")
        children = []
        for child in tree:
            children.append(Predicate.construct(child, nodes_from, flow, can_inspect_results))
        return cls(children)

    def predicates_used(self):
        """
        :return: used predicates by children
        """
        return reduce(lambda x, y: x + y.predicates_used(), self._children, [])

    def nodes_used(self):
        """
        :return: list of nodes that are used
        :rtype: List[Node]
        """
        return reduce(lambda x, y: x + y.nodes_used(), self._children, [])

    def check(self):
        """
        Check predicate for consistency
        """
        for child in self._children:
            child.check()

    def requires_message(self):
        """
        :return: True if any of the children require results of parent task
        """
        return any(child.requires_message() for child in self._children)


class UnaryPredicate(BuiltinPredicate, metaclass=abc.ABCMeta):  # pylint: disable=abstract-method
    """
    Unary predicate abstract class
    """

    def __init__(self, child):
        super().__init__()
        self._child = child

    @staticmethod
    def _create(tree, cls, nodes_from, flow, can_inspect_results):
        """
        Instantiate N-ary predicate cls

        :param tree: node from which should be predicate instantiated
        :type tree: List
        :param cls: class of type NaryPredicate
        :param nodes_from: nodes that are used in described edge
        :param flow: flow to which predicate belongs to
        :param can_inspect_results: True if predicates in the condition can query task result
        :type can_inspect_results: bool
        :return: instance of cls
        """
        if isinstance(tree, list):
            raise ValueError("Unary logical operators expect one child")
        return cls(Predicate.construct(tree, nodes_from, flow, can_inspect_results))

    def predicates_used(self):
        """
        :return: used predicates by children
        """
        return self._child.predicates_used()

    def nodes_used(self):
        """
        :return: list of nodes that are used
        :rtype: List[Node]
        """
        return self._child.nodes_used()

    def check(self):
        """
        Check predicate for consistency
        """
        self._child.check()

    def requires_message(self):
        """
        :return: True if the child requires results of parent task
        """
        return self._child.requires_message()


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
    def create(tree, nodes_from, flow, can_inspect_results):
        """
        Create And predicate

        :param tree: node from which should be predicate instantiated
        :type tree: List
        :param nodes_from: nodes that are used in described edge
        :param flow: flow to which predicate belongs to
        :type flow: Flow
        :param can_inspect_results: True if predicates in the condition can query task result
        :type can_inspect_results: bool
        :return: instance of cls
        """
        return NaryPredicate._create(tree, AndPredicate, nodes_from, flow, can_inspect_results)


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
    def create(tree, nodes_from, flow, can_inspect_results):
        """
        Create Or predicate

        :param tree: node from which should be predicate instantiated
        :type tree: List
        :param nodes_from: nodes that are used in described edge
        :param flow: flow to which predicate belongs to
        :type flow: Flow
        :param can_inspect_results: True if predicates in the condition can query task result
        :type can_inspect_results: bool
        :return: instance of cls
        """
        return NaryPredicate._create(tree, OrPredicate, nodes_from, flow, can_inspect_results)


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
    def create(tree, nodes_from, flow, can_inspect_results):
        """
        Create Or predicate

        :param tree: node from which should be predicate instantiated
        :type tree: List
        :param nodes_from: nodes that are used in described edge
        :param flow: flow to which predicate belongs to
        :type flow: Flow
        :param can_inspect_results: True if predicates in the condition can query task result
        :type can_inspect_results: bool
        :return: instance of cls
        """
        return UnaryPredicate._create(tree, NotPredicate, nodes_from, flow, can_inspect_results)


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

    def nodes_used(self):
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
    def create(tree, nodes_from, flow, can_inspect_results):
        return AlwaysTruePredicate(flow)

    def requires_message(self):
        return False
