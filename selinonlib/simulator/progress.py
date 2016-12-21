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
"""Indicate progress and sleep for given time"""

import sys
from math import ceil
from time import sleep


class Progress(object):
    """Indicate progress and sleep for given time"""
    _indicators = ('-', '\\', '|', '/')
    _current_indicator_idx = 0

    @classmethod
    def indicate(cls, iterable, show_progressbar=True, info_text=None):
        """Indicate progress on iterable

        :param iterable: iterable that is used to iterate on progress
        :param show_progressbar: if True, there is shown a simple ASCII art spinning
        :param info_text: text that is printed on the line (progressbar follows)
        """
        for item in iterable:
            sys.stdout.write(info_text or '')
            if show_progressbar:
                sys.stdout.write(cls._indicators[cls._current_indicator_idx])
                cls._current_indicator_idx = (cls._current_indicator_idx + 1) % len(cls._indicators)

            sys.stdout.flush()
            yield item
            sys.stdout.write('\r')

        # clear whole console line at the end
        sys.stdout.write("\033[K")

    @classmethod
    def sleep(cls, wait_time, sleep_time, info_text=None, show_progressbar=True):
        """Wait and sleep for the given amount of time

        :param wait_time: time to wait in this method in total
        :param sleep_time: time between periodic checks (parameter to sleep() function)
        :param show_progressbar: if True, there is shown a simple ASCII art spinning
        :param info_text: text that is printed on the line (progressbar follows)
        """
        total_wait_time = ceil(wait_time / sleep_time)
        for _ in cls.indicate(range(total_wait_time), show_progressbar, info_text=info_text,):
            sleep(sleep_time)
