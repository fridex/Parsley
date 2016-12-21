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
"""Task and flow failure handling"""

from itertools import chain
from .failureNode import FailureNode


class Failures(object):
    """
    Node failures and fallback handling
    """
    def __init__(self, raw_definition, system, flow, last_allocated=None, starting_nodes=None):
        """
        :param raw_definition: raw definition of failures
        :param system: system context
        :param last_allocated: last allocated starting node for linked list
        :param starting_nodes: starting nodes for failures
        """
        self.waiting_nodes = []
        self.fallback_nodes = []

        for failure in raw_definition:
            waiting_nodes_entry = []
            for node_name in failure['nodes']:
                node = system.node_by_name(node_name, graceful=True)
                if not node:
                    raise KeyError("No such node with name '%s' in failure, flow '%s'" % (node_name, flow.name))
                waiting_nodes_entry.append(node)

            if isinstance(failure['fallback'], list):
                fallback_nodes_entry = []
                for node_name in failure['fallback']:
                    node = system.node_by_name(node_name, graceful=True)
                    if not node:
                        raise KeyError("No such node with name '%s' in failure fallback, flow '%s'"
                                       % (node_name, flow.name))
                    fallback_nodes_entry.append(node)
            elif isinstance(failure['fallback'], bool):
                fallback_nodes_entry = failure['fallback']
            else:
                raise ValueError("Unknown fallback definition in flow '%s', failure: %s" % (flow.name, failure))

            self.waiting_nodes.append(waiting_nodes_entry)
            self.fallback_nodes.append(fallback_nodes_entry)

        self.raw_definition = raw_definition
        self.last_allocated = last_allocated
        self.starting_nodes = starting_nodes

    def all_waiting_nodes(self):
        """
        :return: all nodes that for which there is defined a callback
        """
        return list(set(chain(*self.waiting_nodes)))

    def all_fallback_nodes(self):
        """
        :return: all nodes that are used as fallback nodes
        """
        # remove True/False flags
        nodes = []
        if isinstance(self.fallback_nodes, bool):
            return nodes

        for fallback in self.fallback_nodes:
            if isinstance(fallback, bool):
                continue

            for node in fallback:
                if not isinstance(node, bool):
                    nodes.append(node)

        return list(set(nodes))

    @staticmethod
    def construct(system, flow, failures_dict):
        """
        :param system: system context
        :param flow: a flow to which failures conform
        :param failures_dict: construct failures from failures dict
        :rtype: Failures
        """

        for failure in failures_dict:
            if 'nodes' not in failure or failure['nodes'] is None:
                raise ValueError("Failure should state nodes for state 'nodes' to fallback from in flow '%s'"
                                 % flow.name)

            if 'fallback' not in failure:
                raise ValueError("No fallback stated in failure in flow '%s'" % flow.name)

            if not isinstance(failure['nodes'], list):
                failure['nodes'] = [failure['nodes']]

            if not isinstance(failure['fallback'], list) and failure['fallback'] is not True:
                failure['fallback'] = [failure['fallback']]

            if failure['fallback'] is not True and len(failure['fallback']) == 1 and len(failure['nodes']) == 1 \
                    and failure['fallback'][0] == failure['nodes'][0]:
                raise ValueError("Detect cyclic fallback dependency in flow %s, failure on %s"
                                 % (flow.name, failure['nodes'][0]))

        last_allocated, starting_nodes = FailureNode.construct(flow, failures_dict)
        return Failures(failures_dict, system, flow, last_allocated, starting_nodes)

    @staticmethod
    def starting_nodes_name(flow_name):
        """
        A starting node name representation for generated Python config
        """
        return "_%s_failure_starting_nodes" % flow_name

    @staticmethod
    def failure_node_name(flow_name, failure_node):
        """
        A failure node name representation for generated Python config
        """
        return "_%s_fail_%s" % (flow_name, "_".join(failure_node.traversed))

    def fallback_nodes_names(self):
        """
        :return: names of nodes that are started by fallbacks in all failures
        """
        ret = []

        failure_node = self.last_allocated
        while failure_node:
            if isinstance(failure_node.fallback, list):
                ret.extend(failure_node.fallback)
            failure_node = failure_node.failure_link

        return ret

    def waiting_nodes_names(self):
        """
        :return: names of all nodes that we are expecting to fail for fallbacks
        """
        return list(self.starting_nodes.keys())

    def dump2stream(self, stream, flow_name):
        """
        Dump failures to the Python config file for Dispatcher

        :param stream: output stream to dump to
        :param flow_name: a name of a flow that failures belong to
        """
        fail_node = self.last_allocated

        while fail_node:
            next_dict = {}
            for key, value in fail_node.next.items():
                next_dict[key] = self.failure_node_name(flow_name, value)

            stream.write("%s = {'next': " % self.failure_node_name(flow_name, fail_node))

            # print "next_dict"
            stream.write('{')
            printed = False
            for key, value in next_dict.items():
                if printed:
                    stream.write(", ")
                stream.write("'%s': %s" % (key, value))
                printed = True
            stream.write('}, ')

            # now list of nodes that should be started in case of failure (fallback)
            stream.write("'fallback': %s}\n" % fail_node.fallback)
            fail_node = fail_node.failure_link

        stream.write("\n%s = {" % self.starting_nodes_name(flow_name))

        printed = False
        for key, value in self.starting_nodes.items():
            if printed:
                stream.write(",")
            stream.write("\n    '%s': %s" % (key, self.failure_node_name(flow_name, value)))
            printed = True
        stream.write("\n}\n\n")
