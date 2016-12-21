#!/usr/bin/env python3
"""Implementation of some well-known caches for Selinon"""

from .cacheMissError import CacheMissError
from .fifo import FIFO
from .lifo import LIFO
from .mru import MRU
from .lru import LRU
from .rr import RR
