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
"""A flow representation"""

import logging
from .edge import Edge
from .node import Node
from .failures import Failures
from .strategy import Strategy
from .globalConfig import GlobalConfig


class Flow(Node):  # pylint: disable=too-many-instance-attributes
    """
    Flow representation
    """

    _logger = logging.getLogger(__name__)

    def __init__(self, name, edges=None, failures=None, nowait_nodes=None, queue_name=None, strategy=None):
        """
        :param name: flow name
        :type name: str
        :param edges: edges in the flow
        :type edges: List[Edge]
        :param nowait_nodes: nodes that should not be waited for
        :type nowait_nodes: List[Node]
        :param queue_name: queue where the dispatcher should listen on
        :type queue_name: str
        :param strategy: a strategy to be used for scheduling dispatcher
        """
        super().__init__(name)

        self._logger.debug("Creating flow '%s'", name)
        self.edges = edges or []
        self.failures = failures or None
        self.nowait_nodes = nowait_nodes or []
        self.node_args_from_first = False
        self.queue_name = queue_name
        self.strategy = strategy

        self.propagate_node_args = False
        self.propagate_finished = False
        self.propagate_parent = False
        self.propagate_compound_finished = False
        self.throttle = None

    @staticmethod
    def from_dict(d):
        # We do not use this method, as we expect flow listings and flow definitions in a separate sections due to
        # chicken-egg issues in flows
        raise NotImplementedError()

    def _set_propagate(self, system, flow_def, propagate_type):
        """
        Parse propagate_node_args flag and adjust flow accordingly

        :param system: system that is used
        :param flow_def: flow definition
        :param propagate_type: propagate flag type
        """
        ret = False

        if propagate_type in flow_def and flow_def[propagate_type] is not None:
            if not isinstance(flow_def[propagate_type], list) and \
                    not isinstance(flow_def[propagate_type], bool):
                flow_def[propagate_type] = [flow_def[propagate_type]]

            if isinstance(flow_def[propagate_type], list):
                ret = []  # pylint: disable=redefined-variable-type
                for node_name in flow_def[propagate_type]:
                    node = system.flow_by_name(node_name)
                    ret.append(node)
            elif isinstance(flow_def[propagate_type], bool):
                ret = flow_def[propagate_type]
            else:
                raise ValueError("Unknown value in '%s' in flow %s" % (self.name, propagate_type))

        return ret

    def parse_definition(self, flow_def, system):
        """
        Parse flow definition (fill flow attributes) from a dictionary

        :param flow_def: dictionary containing flow definition
        :param system: system in which flow is defined
        """
        assert flow_def['name'] == self.name

        if len(self.edges) > 0:
            raise ValueError("Multiple definitions of flow '%s'" % self.name)

        for edge_def in flow_def['edges']:
            edge = Edge.from_dict(edge_def, system, self)
            self.add_edge(edge)

        if 'failures' in flow_def:
            failures = Failures.construct(system, self, flow_def['failures'])
            self.failures = failures

        if 'nowait' in flow_def and flow_def['nowait'] is not None:
            if not isinstance(flow_def['nowait'], list):
                flow_def['nowait'] = [flow_def['nowait']]

            for node_name in flow_def['nowait']:
                node = system.node_by_name(node_name)
                self.add_nowait_node(node)

        self.throttle = self.parse_throttle(flow_def)
        self.node_args_from_first = flow_def.get('node_args_from_first', False)
        self.propagate_node_args = self._set_propagate(system, flow_def, 'propagate_node_args')
        self.propagate_finished = self._set_propagate(system, flow_def, 'propagate_finished')
        self.propagate_parent = self._set_propagate(system, flow_def, 'propagate_parent')
        self.propagate_compound_finished = self._set_propagate(system, flow_def, 'propagate_compound_finished')
        self.queue_name = flow_def.get('queue', GlobalConfig.default_dispatcher_queue)
        self.strategy = Strategy.from_dict(flow_def.get('sampling'), self.name)

    def add_edge(self, edge):
        """
        :param edge: edge to be added
        :type edge: List[Edge]
        """
        self.edges.append(edge)

    def add_nowait_node(self, node):
        """
        :param node: add a node that should be marked with nowait flag
        """
        self.nowait_nodes.append(node)

    def all_nodes_from(self):
        """
        :return: all source nodes in flow, excluding failures
        """
        all_nodes_from = set()

        for edge in self.edges:
            all_nodes_from = all_nodes_from | set(edge.nodes_from)

        return list(all_nodes_from)

    def all_nodes_to(self):
        """
        :return: all destination nodes in flow, excluding failures
        """
        all_nodes_to = set()

        for edge in self.edges:
            all_nodes_to = all_nodes_to | set(edge.nodes_to)

        return list(all_nodes_to)

    def all_source_nodes(self):
        """
        :return: all source nodes in flow, including failures
        """
        if self.failures:
            return list(set(self.all_nodes_from()) | set(self.failures.all_waiting_nodes()))
        else:
            return self.all_nodes_from()

    def all_destination_nodes(self):
        """
        :return: all destination nodes in flow, including failures
        """
        if self.failures:
            return list(set(self.all_nodes_to()) | set(self.failures.all_fallback_nodes()))
        else:
            return self.all_nodes_to()

    def all_used_nodes(self):
        """
        :return: all used nodes in flow
        """
        return list(set(self.all_destination_nodes()) | set(self.all_source_nodes()))

    @staticmethod
    def _should_config(dst_node_name, configuration):
        """
        :param dst_node_name: destination node to which configuration should be propagated
        :param configuration: configuration that should be checked
        :return: true if node_name satisfies configuration
        """
        if configuration is True:
            return True

        if isinstance(configuration, list):
            return dst_node_name in configuration

        return False

    def should_propagate_finished(self, dst_node_name):
        """
        :param dst_node_name: destination node to which configuration should be propagated
        :return: True if should propagate_finish
        """
        return self._should_config(dst_node_name, self.propagate_finished)

    def should_propagate_node_args(self, dst_node_name):
        """
        :param dst_node_name: destination node to which configuration should be propagated
        :return: True if should propagate_node_args
        """
        return self._should_config(dst_node_name, self.propagate_node_args)

    def should_propagate_parent(self, dst_node_name):
        """
        :param dst_node_name: destination node to which configuration should be propagated
        :return: True if should propagate_parent
        """
        return self._should_config(dst_node_name, self.propagate_parent)

    def should_propagate_compound_finished(self, dst_node_name):  # pylint: disable=invalid-name
        """
        :param dst_node_name: destination node to which configuration should be propagated
        :return: True if should propagate_compound_finished
        """
        return self._should_config(dst_node_name, self.propagate_compound_finished)
