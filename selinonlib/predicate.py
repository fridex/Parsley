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
Predicate interface - predicate for building conditions
"""

import abc
from .helpers import dict2json


class Predicate(metaclass=abc.ABCMeta):
    """
    An abstract predicate representation
    """
    @abc.abstractmethod
    def __init__(self):
        pass

    @abc.abstractmethod
    def __str__(self):
        pass

    @abc.abstractclassmethod
    def create(cls, tree, nodes_from, flow):
        """
        Create the predicate

        :param nodes_from: nodes which are used within edge definition
        :type nodes_from: List[Nodes]
        :param flow: flow to which predicate belongs to
        :type flow: Flow
        :return: Predicate instance
        """
        pass

    @abc.abstractmethod
    def ast(self):
        """
        :return: AST representation of predicate
        """
        pass

    @abc.abstractmethod
    def predicates_used(self):
        """
        :return: list of predicates that are used
        :rtype: List[Predicate]
        """
        pass

    @staticmethod
    def construct(tree, nodes_from, flow):  # pylint: disable=too-many-branches
        """
        Top-down creation of predicates - recursively called to construct predicates

        :param tree: a dictionary describing nodes
        :type tree: dict
        :param nodes_from: nodes which are used within edge
        :param flow: flow to which predicate belongs to
        :type flow: Flow
        :rtype: Predicate
        """
        from .leafPredicate import LeafPredicate
        from .builtinPredicate import OrPredicate, AndPredicate, NotPredicate

        if not tree:
            raise ValueError("Bad condition '%s'" % tree)

        if 'name' in tree:
            if 'node' in tree:
                node = None
                for node_from in nodes_from:
                    if node_from.name == tree['node']:
                        node = node_from
                        break
                if node is None:
                    raise ValueError("Node listed node '%s' in predicate '%s' is not requested in 'nodes_from'"
                                     % (tree['node'], tree['name']))
            else:
                if len(nodes_from) > 1:
                    raise ValueError("Expected task name for predicate '%s'" % tree['name'])
                elif len(nodes_from) == 1:
                    node = nodes_from[0]
                else:
                    # e.g. starting edge has no nodes_from
                    node = None

            return LeafPredicate.create(tree['name'], node, flow, tree.get('args'))
        elif 'or' in tree:
            return OrPredicate.create(tree['or'], nodes_from, flow)
        elif 'not' in tree:
            return NotPredicate.create(tree['not'], nodes_from, flow)
        elif 'and' in tree:
            return AndPredicate.create(tree['and'], nodes_from, flow)
        else:
            raise ValueError("Unknown predicate:\n%s" % dict2json(tree))

    @abc.abstractmethod
    def check(self):
        """
        Recursively check predicate correctness

        :raises ValueError: if predicate is not correct
        """
        pass
