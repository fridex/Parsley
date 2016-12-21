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
Least-Recently-Used cache implementation
"""

from .cache import Cache
from .cacheMissError import CacheMissError


class _Record(object):
    """
    Record that is used in a double-linked list in order to track usage
    """
    def __init__(self, item_id, item):
        self.item_id = item_id
        self.item = item
        self.previous = None
        self.next = None

    def __repr__(self):
        return "<%s>" % self.item_id


class LRU(Cache):
    """
    Least-Recently-Used cache
    """
    def __init__(self, max_cache_size):
        # let's allow zero size
        assert max_cache_size >= 0

        self.max_cache_size = max_cache_size
        self._cache = {}

        self._record_head = None
        self._record_tail = None
        self.current_cache_size = 0

    def __repr__(self):
        records = []

        record = self._record_head
        while record:
            records.append(record.item_id)
            record = record.previous

        return "%s(%s)" % (self.__class__.__name__, records)

    def _add_record(self, record):
        """
        Add record to cache, record shouldn't be present in the cache

        :param record: record to add to cache
        """
        self._cache[record.item_id] = record
        self.current_cache_size += 1

        if not self._record_head:
            self._record_head = record

        if self._record_tail:
            record.next = self._record_tail
            self._record_tail.previous = record

        record.next = self._record_tail
        self._record_tail = record

    def _remove_record(self, record):
        """
        Remove record from cache, record should be present in the cache

        :param record: record to be deleted
        """
        del self._cache[record.item_id]
        self.current_cache_size -= 1

        if record.next:
            record.next.previous = record.previous

        if record.previous:
            record.previous.next = record.next

        if record == self._record_tail:
            self._record_tail = record.next

        if record == self._record_head:
            self._record_head = record.previous

        record.next = None
        record.previous = None

    def _clean_cache(self):
        """
        Trim cache
        """
        while self.current_cache_size + 1 > self.max_cache_size and self.current_cache_size > 0:
            self._remove_record(self._record_head)

    def add(self, item_id, item, task_name, flow_name):
        """
        Add item to cache

        :param item_id: item id under which item should be referenced
        :param item: item itself
        :param task_name: name of task that result should/shouldn't be cached
        :param flow_name: name of flow in which task was executed
        """
        if item_id in self._cache:
            # we mark usage only in get()
            return

        self._clean_cache()

        if self.max_cache_size > 0:
            record = _Record(item_id, item)
            self._add_record(record)

    def get(self, item_id, task_name, flow_name):
        """
        Get item from cache

        :param item_id: item id under which the item is stored
        :param task_name: name of task that result should/shouldn't be cached in order to get
        :param flow_name: name of flow in which task was executed in order to get result
        :return: item itself
        """
        record = self._cache.get(item_id)

        # this if is safe as we store tuple - we handle even None results
        if not record:
            raise CacheMissError()

        # mark record usage
        self._remove_record(record)
        self._add_record(record)

        return record.item
