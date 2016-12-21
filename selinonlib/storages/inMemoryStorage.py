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
In memory storage implementation
"""

import sys
import json as jsonlib
from .dataStorage import DataStorage


class InMemoryStorage(DataStorage):
    """
    Storage that stores results in memory without persistence
    """
    def __init__(self, echo=False, json=False):
        """
        :param echo: echo results to stdout/stderr - provide 'stderr' or 'stdout' to echo data retrieval and storing
        :param json: if True a JSON will be printed
        """
        super(InMemoryStorage, self).__init__()
        self.database = {}
        self.echo_file = None

        if not echo and json:
            raise ValueError("JSON parameter requires echo to be specified ('stdout' or 'stderr')")

        self.echo_json = json

        if echo == 'stdout' or echo is True:
            self.echo_file = sys.stdout
        elif echo == 'stderr':
            self.echo_file = sys.stderr

    def is_connected(self):
        return True

    def connect(self):
        pass

    def disconnect(self):
        pass

    def retrieve(self, task_name, task_id):
        try:
            result = self.database[task_id]['result']
            if self.echo_file and self.echo_json:
                jsonlib.dump(result, self.echo_file, sort_keys=True, separators=(',', ': '), indent=2)
            elif self.echo_file:
                print(result, file=self.echo_file)
        except KeyError:
            raise FileNotFoundError("Record not found in database")

    def store(self, node_args, flow_name, task_name, task_id, result):
        assert task_id not in self.database

        record = {
            'node_args': node_args,
            'task_name': task_name,
            'flow_name': flow_name,
            'task_id': task_id,
            'result': result
        }
        self.database[task_id] = record

        if self.echo_file and self.echo_json:
            jsonlib.dump(record, self.echo_file, sort_keys=True, separators=(',', ': '), indent=2)
        elif self.echo_file:
            print(record, file=self.echo_file)

        # task_id is unique for the record
        return task_id
