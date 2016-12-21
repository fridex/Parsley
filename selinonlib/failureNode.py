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

r"""
A failure is basically a node in graph, that represents all permutations of possible cases of failures. Consider
having two failure conditions:

.. code-block:: yaml

  failures:
    - nodes:
          - Task1
          - Task2
          - Task3
      fallback:
          - FallbackTask1
    - nodes:
          - Task1
          - Task2
      fallback:
          - FallbackTask2

What we do here, we construct a graph of all possible permutations connected using edges that represent a node
that should be added to create a new permutation:

.. code-block:: yaml

   |-------------------------------
   |                              |
  T1           T2           T3    |
    \         /  \         / \    |
     \       /    \       /   \   |
      \     /      \     /     \  v
       T1,T2*       T2,T3      T1,T3
          \         /           /
           \       /           /
            T1,T2,T3*  <-------

For nodes ``T1,T2,T3`` and ``T1,T2`` we assign a fallback as configured. This graph is then serialized into the Python
configuration code. This way the dispatcher has O(N) time complexity when dealing with failures.

Note we are creating sparse tree - only for nodes that are listed in failures.

Note that we link failure nodes as allocated - we get a one way linked list of all failure nodes that helps us with
Python code generation.
"""

from functools import reduce


class FailureNode(object):
    """
    A representation of a failure node permutation
    """
    def __init__(self, flow, traversed, failure_link):
        """
        :param flow: flow to which the failure node conforms to
        :param traversed: traversed nodes - also permutation of nodes
        :param failure_link: link to next failure node in failures
        """
        self.next = {}
        self.flow = flow
        self.fallback = []
        self.traversed = traversed
        self.failure_link = failure_link

    def to(self, node_name):  # pylint: disable=invalid-name
        """
        Retrieve next permutation

        :param node_name: a name of the node for next permutation
        :rtype: FailureNode
        """
        return self.next[node_name]

    def has_to(self, node_name):
        """
        :param node_name:
        :return: True if there is a link to next permutation for node of name node_name
        """
        return node_name in self.next

    def add_to(self, node_name, failure):
        """
        Add failure for next permutation

        :param node_name: a node for next permutation
        :param failure: FailureNode that should be added
        """
        assert node_name not in self.next
        self.next[node_name] = failure

    @staticmethod
    def _add_fallback(failure_node, fallback):
        if len(failure_node.fallback) > 0:
            raise ValueError("Multiple definitions of a failure in flow '%s' with failure of %s"
                             % (failure_node.flow.name, failure_node.traversed))

        if not isinstance(fallback, list) and fallback is not True:
            fallback = [fallback]

        # additional checks are done by System
        failure_node.fallback = fallback

    @classmethod
    def construct(cls, flow, failures):  # pylint: disable=too-many-locals,too-many-branches
        """
        Construct failures from failures dictionary

        :param failures: failures dictionary
        :param flow: flow to which failures conform to
        :return: a link for linked list of failures and a dict of starting failures
        """
        last_allocated = None
        starting_failures = {}

        # pylint: disable=too-many-nested-blocks
        for failure in failures:
            used_starting_failures = {}

            for node in failure['nodes']:
                if node not in starting_failures:
                    failure_node = FailureNode(flow, [node], last_allocated)
                    last_allocated = failure_node
                    starting_failures[node] = failure_node
                    used_starting_failures[node] = failure_node
                else:
                    used_starting_failures[node] = starting_failures[node]

            current_nodes = list(used_starting_failures.values())
            next_nodes = []

            for _ in range(1, len(failure['nodes'])):  # for every permutation length

                for edge_node in failure['nodes']:  # edge_node is a node that can create a new permutation from a node

                    for current_node in current_nodes:

                        if edge_node not in current_node.traversed:

                            if not current_node.has_to(edge_node):
                                next_node = current_node.traversed + [edge_node]
                                failure_node = FailureNode(flow, next_node, last_allocated)
                                last_allocated = failure_node
                                current_node.add_to(edge_node, failure_node)

                                for node in current_nodes:
                                    diff = set(node.traversed) ^ set(next_node)

                                    if len(diff) == 1:
                                        if not node.has_to(list(diff)[0]):
                                            node.add_to(list(diff)[0], failure_node)

                                next_nodes.append(failure_node)
                            else:
                                # keep for generating new permutations
                                next_nodes.append(current_node.to(edge_node))

                current_nodes = next_nodes
                next_nodes = []

            failure_node = reduce(lambda x, y: x.to(y),
                                  failure['nodes'][1:],
                                  used_starting_failures[failure['nodes'][0]])
            cls._add_fallback(failure_node, failure['fallback'])

        # we could make enumerable and avoid last_allocated (it would be cleaner), but let's stick with
        # this one for now
        return last_allocated, starting_failures
