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

"""Injected Celery related implementations of methods, classes and functions to make Selinon simulator work
as a standalone CLI"""

from flexmock import flexmock


class SimulateRequest(object):
    """Simulate Celery's Task.request in order to be able to query task id right inside task by calling
    self.request.id"""
    def __init__(self, instance):
        self.id = str(id(instance))  # pylint: disable=redefined-builtin,invalid-name


class SimulateAsyncResult(object):
    """Simulate AsyncResult returned by apply_async() or by instantiating AsyncResult by Task id"""
    task_failures = {}
    task_successes = {}

    def __init__(self, id):  # pylint: disable=redefined-builtin,invalid-name
        self.task_id = str(id)

    @classmethod
    def set_successful(cls, task_id, result):
        """Mark task as successful after run - called by simulator

        :param task_id: an ID of task that should be marked as successful
        :param result: result of task (None for SelinonTaskEnvelope, JSON describing system state for Dispatcher)
        """
        cls.task_successes[task_id] = result

    @classmethod
    def set_failed(cls, task_id, exception):
        """Mark task as failed after run - called by simulator

        :param task_id: an ID of task that should be marked as failed
        :param exception: exception raised in task
        """
        cls.task_failures[task_id] = exception

    def successful(self):
        """
        :return: True if task succeeded
        """
        return self.task_id in self.task_successes

    def failed(self):
        """
        :return: True if task failed
        """
        return self.task_id in self.task_failures

    @property
    def result(self):
        """
        :return: retrieve result of the task or exception that was raised
        """
        return self.task_failures.get(self.task_id, None)


class SimulateRetry(Exception):
    """Simulate Celery Retry exception raised by self.retry()"""
    def __init__(self, instance, **celery_kwargs):
        super().__init__()
        self.instance = instance
        self.celery_kwargs = celery_kwargs


def simulate_apply_async(instance, **celery_kwargs):
    """Simulate CeleryTask().apply_async() implementation for scheduling tasks

    :param instance: instance that should be scheduled
    :param celery_kwargs: kwargs supplied to Celery Task (also carry arguments for Selinon)
    """
    from .simulator import Simulator

    flexmock(instance, request=SimulateRequest(instance))
    Simulator.schedule(instance, celery_kwargs)
    return SimulateAsyncResult(id=id(instance))


def simulate_retry(instance, **celery_kwargs):
    """Simulate Celery self.retry() implementation for retrying tasks

    :param instance: instance that should called self.retry()
    :param celery_kwargs: kwargs that will be supplied to Celery Task (also carry arguments for Selinon)
    """
    raise SimulateRetry(instance, **celery_kwargs)
