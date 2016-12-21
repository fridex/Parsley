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
from selinonlib.caches import (RR, CacheMissError)


class TestRR(object):
    """
    Test Random-Replacement Cache
    """
    def test_remove(self):
        cache = RR(max_cache_size=1)

        cache.add("item_id1", "item1", "Task1", "flow1")
        assert cache.get("item_id1", "Task1", "flow1") == "item1"

        cache.add("item_id2", "item2", "Task1", "flow1")
        assert cache.get("item_id2", "Task1", "flow1") == "item2"

        with pytest.raises(CacheMissError):
            cache.get("item_id1", "Task1", "flow1")

    def test_random_remove(self):
        cache = RR(max_cache_size=2)

        cache.add("item_id1", "item1", "Task1", "flow1")
        cache.add("item_id2", "item2", "Task1", "flow1")
        cache.add("item_id3", "item3", "Task1", "flow1")

        with pytest.raises(CacheMissError):
            # at least one should fail
            cache.get("item_id1", "Task1", "flow1")
            cache.get("item_id2", "Task1", "flow1")

        assert cache.get("item_id3", "Task1", "flow1") == "item3"
        assert cache.current_cache_size == 2
