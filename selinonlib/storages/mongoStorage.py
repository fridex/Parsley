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
MongoDB database adapter
"""

from pymongo import MongoClient
from .dataStorage import DataStorage


class MongoStorage(DataStorage):
    """
    MongoDB database adapter
    """
    def __init__(self, db_name, collection_name, host="localhost", port=27017):
        super(MongoStorage, self).__init__()
        self.client = None
        self.collection = None
        self.db = None  # pylint: disable=invalid-name
        self.host = host
        self.port = port
        self.db_name = db_name
        self.collection_name = collection_name

    def is_connected(self):
        return self.client is not None

    def connect(self):
        self.client = MongoClient(self.host, self.port)
        self.db = self.client[self.db_name]
        self.collection = self.db[self.collection_name]

    def disconnect(self):
        if self.is_connected():
            self.client.close()
            self.client = None
            self.db = None
            self.collection = None

    def retrieve(self, task_name, task_id):
        assert self.is_connected()

        filtering = {'_id': 0}
        cursor = self.collection.find({'task_id': task_id}, filtering)

        if len(cursor) > 0:
            raise ValueError("Multiple records with same task_id found")
        elif len(cursor) == 0:
            raise FileNotFoundError("Record not found in database")

        record = cursor[0]

        assert task_name == record['task_name']
        return record.get('result')

    def store(self, node_args, flow_name, task_name, task_id, result):
        assert self.is_connected()

        record = {
            'flow_name': flow_name,
            'node_args': node_args,
            'task_name': task_name,
            'task_id': task_id,
            'result': result

        }

        self.collection.insert(record)

        # task_id is unique here
        return task_id
