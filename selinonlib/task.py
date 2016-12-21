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
"""A task representation from YAML config file"""

import logging
from .node import Node
from .globalConfig import GlobalConfig

_DEFAULT_MAX_RETRY = 0
_DEFAULT_RETRY_COUNTDOWN = 0


class Task(Node):
    # pylint: disable=too-many-instance-attributes,arguments-differ
    """
    A task representation within the system
    """
    _logger = logging.getLogger(__name__)

    def __init__(self, name, import_path, storage, opts):
        """
        :param name: name of the task
        :param import_path: tasks's import
        :param storage: storage that should be used
        :param opts: additional options for task
        """
        super(Task, self).__init__(name)

        self.class_name = opts.get('classname', name)
        self.storage_task_name = opts.get('storage_task_name', name)
        self.output_schema = opts.get('output_schema')
        self.max_retry = opts.get('max_retry', _DEFAULT_MAX_RETRY)
        self.retry_countdown = opts.get('retry_countdown', _DEFAULT_RETRY_COUNTDOWN)
        self.queue_name = opts.get('queue', GlobalConfig.default_task_queue)
        self.import_path = import_path
        self.storage = storage
        self.storage_readonly = opts.get('storage_readonly', False)
        self.throttle = self.parse_throttle(opts)

        # register task usage
        if self.storage:
            storage.register_task(self)
        self._logger.debug("Creating task with name '%s' import path '%s', class name '%s'",
                           self.name, self.import_path, self.class_name)

    def check(self):
        """
        Check task definitions for errors

        :raises: ValueError if an error occurred
        """
        if not isinstance(self.import_path, str):
            raise ValueError("Error in task '%s' definition - import path should be string; got '%s'"
                             % (self.name, self.import_path))

        if self.class_name is not None and not isinstance(self.class_name, str):
            raise ValueError("Error in task '%s' definition - class instance should be string; got '%s'"
                             % (self.name, self.class_name))

        if self.output_schema is not None and not isinstance(self.output_schema, str):
            raise ValueError("Error in task '%s' definition - output schema should be string; got '%s'"
                             % (self.name, self.output_schema))

        if self.max_retry is not None and (not isinstance(self.max_retry, int) or self.max_retry < 0):
            raise ValueError("Error in task '%s' definition - max_retry should be None, zero or positive integer;"
                             " got '%s'" % (self.name, self.max_retry))

        if self.retry_countdown is not None and (not isinstance(self.retry_countdown, int) or self.retry_countdown < 0):
            raise ValueError("Error in task '%s' definition - retry_countdown should be None or positive integer;"
                             " got '%s'" % (self.name, self.retry_countdown))

        if self.queue_name is not None and not isinstance(self.queue_name, str):
            raise ValueError("Invalid task queue, should be string, got %s" % self.queue_name)

        if not isinstance(self.storage_readonly, bool):
            raise ValueError("Storage usage flag readonly should be of type bool")

    @staticmethod
    def from_dict(d, system):
        """
        Construct task from a dict and check task's definition correctness

        :param d: dictionary to be used to construct the task
        :return: Task instance
        :param system: system that should be used to for lookup a storage
        :type system: System
        :rtype: Task
        :raises: ValueError
        """
        if 'name' not in d or not d['name']:
            raise KeyError('Task name definition is mandatory')
        if 'import' not in d or not d['import']:
            raise KeyError('Task import definition is mandatory')
        if 'storage' in d:
            storage = system.storage_by_name(d['storage'])
        else:
            storage = None

        instance = Task(d['name'], d['import'], storage, d)
        instance.check()
        return instance
