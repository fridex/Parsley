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
Random replacement cache implementation
"""

import random
from .cache import Cache
from .cacheMissError import CacheMissError


class RR(Cache):
    """
    Random replacement cache
    """
    def __init__(self, max_cache_size):
        assert max_cache_size >= 0

        self.max_cache_size = max_cache_size
        self._cache = {}

    @property
    def current_cache_size(self):
        """
        :return: current cache size
        """
        return len(list(self._cache.keys()))

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, list(self._cache.keys()))

    def add(self, item_id, item, task_name, flow_name):
        """
        Add item to cache

        :param item_id: item id under which item should be referenced
        :param item: item itself
        :param task_name: name of task that result should/shouldn't be cached
        :param flow_name: name of flow in which task was executed
        """
        if item_id in self._cache:
            return

        while self.current_cache_size + 1 > self.max_cache_size and self.current_cache_size > 0:
            to_remove = random.choice(list(self._cache.keys()))
            del self._cache[to_remove]

        if self.max_cache_size > 0:
            self._cache[item_id] = item

    def get(self, item_id, task_name, flow_name):
        """
        Get item from cache

        :param item_id: item id under which the item is stored
        :param task_name: name of task that result should/shouldn't be cached in order to get
        :param flow_name: name of flow in which task was executed in order to get result
        :return: item itself
        """
        if item_id not in self._cache:
            raise CacheMissError()

        return self._cache[item_id]
