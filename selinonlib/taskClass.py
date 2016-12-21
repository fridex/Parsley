#!/usr/bin/env python3
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
"""A Python class abstraction"""


class TaskClass(object):
    """
    Task's class abstraction
    """
    def __init__(self, class_name, import_path):
        self.class_name = class_name
        self.import_path = import_path
        self.tasks = []

    def task_of_class(self, task):
        """
        :param task: task to be checked
        :return: True if task is of this class
        """
        return self.class_name == task.class_name and self.import_path == task.import_path

    def add_task(self, task):
        """
        Register a task to this class

        :param task: task to be added
        """
        assert self.task_of_class(task)
        self.tasks.append(task)
