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
"""Abstract representation of nodes in task/flow dependencies - a node is either a task or a flow"""

import datetime
import abc
import re


class Node(metaclass=abc.ABCMeta):
    """
    An abstract class for node representation
    """
    def __init__(self, name):
        if not self.check_name(name):
            raise ValueError("Invalid node name '%s'" % name)
        self._name = name

    @abc.abstractstaticmethod
    def from_dict(dict_):
        """
        Construct node from a dict

        :return: instantiated node
        """
        pass

    @property
    def name(self):
        """
        :return: a name of the node
        """
        return self._name

    def is_flow(self):
        """
        :return: True if node represents a Flow
        """
        from .flow import Flow
        return isinstance(self, Flow)

    def is_task(self):
        """
        :return: True if node represents a Task
        """
        from .task import Task
        return isinstance(self, Task)

    @staticmethod
    def check_name(name):
        """
        Check whether name is a correct node (flow/task) name

        :param name: node name
        :return: True if name is a correct node name
        :rtype: bool
        """
        regexp = re.compile(r"^[_a-zA-Z][_a-zA-Z0-9]*$")
        return regexp.match(name)

    def parse_throttle(self, dict_):
        """
        Parse throttle from a dictionary

        :param dict_: dictionary from which throttle should be parsed (expected under 'throttle' key)
        :return: timedelta describing throttle countdown
        :rtype: time.timedelta
        """
        if 'throttle' in dict_:
            if not isinstance(dict_['throttle'], dict):
                raise ValueError("Definition of throttle expects key value definition, got %s instead in '%s'"
                                 % (dict_['throttle'], self.name))
            try:
                return datetime.timedelta(**dict_['throttle'])
            except TypeError:
                raise ValueError("Wrong throttle definition in '%s', expected values are %s"
                                 % (self.name,
                                    ['days', 'seconds', 'microseconds', 'milliseconds', 'minutes', 'hours', 'weeks']))
        else:
            return None
