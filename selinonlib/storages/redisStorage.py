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
Selinon adapter for Redis database
"""

import json
import redis
from .dataStorage import DataStorage


class RedisStorage(DataStorage):  # pylint: disable=too-many-instance-attributes
    """
    Selinon adapter for Redis database
    """
    def __init__(self, host="localhost", port=6379, db=0, password=None, socket_timeout=None, connection_pool=None,
                 charset='utf-8', errors='strict', unix_socket_path=None):
        super().__init__()
        self.conn = None
        self.host = host
        self.port = port
        self.db = db  # pylint: disable=invalid-name
        self.password = password
        self.socket_timeout = socket_timeout
        self.connection_pool = connection_pool
        self.charset = charset
        self.errors = errors
        self.unix_socket_path = unix_socket_path

    def is_connected(self):
        return self.conn is not None

    def connect(self):
        self.conn = redis.Redis(host=self.host, port=self.port, db=self.db, password=self.password,
                                socket_timeout=self.socket_timeout, connection_pool=self.connection_pool,
                                charset=self.charset, errors=self.errors)

    def disconnect(self):
        if self.is_connected():
            self.conn.connection_pool.disconnect()
            self.conn = None

    def retrieve(self, task_name, task_id):
        assert self.is_connected()

        ret = self.conn.get(task_id)

        if ret is None:
            raise FileNotFoundError("Record not found in database")

        record = json.loads(ret.decode(self.charset))

        assert record.get('task_name') == task_name
        return record.get('result')

    def store(self, node_args, flow_name, task_name, task_id, result):
        assert self.is_connected()

        record = {
            'node_args': node_args,
            'flow_name': flow_name,
            'task_name': task_name,
            'task_id': task_id,
            'result': result
        }

        self.conn.set(task_id, json.dumps(record))
        return task_id
