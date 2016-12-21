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

import pytest
from selinonlib.caches import (MRU, CacheMissError)


class TestMRU(object):
    """
    Test Most-Recently-Used cache
    """
    @staticmethod
    def _item_id2item(i):
        return "x%s" % i

    def test_one_item_miss(self):
        cache = MRU(max_cache_size=1)

        cache.add("item_id1", "item1", "Task1", "flow1")
        cache.add("item_id2", "item2", "Task1", "flow1")

        with pytest.raises(CacheMissError):
            cache.get("item_id1", "Task1", "flow1")

    def test_two_items(self):
        cache = MRU(max_cache_size=2)

        cache.add("item_id1", "item1", "Task1", "flow1")
        cache.add("item_id2", "item2", "Task1", "flow1")
        cache.add("item_id3", "item3", "Task1", "flow1")

        with pytest.raises(CacheMissError):
            cache.get("item_id2", "Task1", "flow1")

        assert cache.get("item_id1", "Task1", "flow1") == "item1"
        assert cache.get("item_id3", "Task1", "flow1") == "item3"

        # we made "item2" a candidate for next deletion as "item3" was used lastly
        cache.add("item_id1", "item1", "Task1", "flow1")
        with pytest.raises(CacheMissError):
            cache.get("item_id2", "Task1", "flow1")

    def test_multiple_items(self):
        item_count = 16
        cache = MRU(max_cache_size=item_count)

        for item_id in range(item_count):
            cache.add(item_id, self._item_id2item(item_id), "Task1", "flow1")

        cache.add(item_count, self._item_id2item(item_count), "Task1", "flow1")

        with pytest.raises(CacheMissError):
            # the very last is removed
            cache.get(item_count - 1, "Task1", "flow1")

        for item_id in range(item_count - 2, -1, -1):
            assert cache.get(item_id, "Task1", "flow1") == self._item_id2item(item_id)

        assert cache.get(item_count, "Task1", "flow1") == self._item_id2item(item_count)

        # re-add 0
        cache.add(0, self._item_id2item(0), "Task1", "flow1")

        with pytest.raises(CacheMissError):
            cache.get(item_count - 1, "Task1", "flow1")

        for item_id in range(item_count - 1):
            assert cache.get(item_id, "Task1", "flow1") == self._item_id2item(item_id)

        assert cache.get(item_count, "Task1", "flow1") == self._item_id2item(item_count)

    def test_multiple_items_get(self):
        item_count = 16
        cache = MRU(max_cache_size=item_count)

        for item_id in range(item_count):
            cache.add(item_id, self._item_id2item(item_id), "Task1", "flow1")

        # let's use the following 5 items, so they get to the front
        used_items = [10, 5, 3, 1, 7]
        for item_id in used_items:
            assert cache.get(item_id, "Task1", "flow1") == self._item_id2item(item_id)

        # add 5 dummy elements
        for item_id in range(1, 6):
            cache.add(item_id*100, self._item_id2item(item_id*100), "Task1", "flow1")

        with pytest.raises(CacheMissError):
            # last item that was used
            cache.get(used_items[-1], "Task1", "flow1")

        for item_id in range(1, 5):
            with pytest.raises(CacheMissError):
                cache.get(item_id*100, "Task1", "flow1") == self._item_id2item(item_id*100)

        # last inserted when adding 5 dummy elements
        assert cache.get(500, "Task1", "flow1") == self._item_id2item(500)
