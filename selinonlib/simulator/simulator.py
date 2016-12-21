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
"""Using Selinon simulator is a good way to test you configuration and behaviour locally if you would like to save
some time when debugging or exploring all the possibilities that Selinon offers you. Keep in mind that running
Selinon locally was designed for development purposes and behaviour in general can (and in many cases will) vary.

The key idea behind simulator is to simulate exchange of messages which is done by your Celery broker and Kombu under
the hood of Celery. Thus there are lazily created queues that are referenced by their names (see
selinonlib.simulator.timeQueue for implementation details). These queues hold messages prior to time on which they were
scheduled. Under the hood there is used a heap queue to optimize inserting to O(log(N)) in the worst case where N is
number messages currently in the queue. These queues are coupled into QueuePool (selinonlib.simulate.queuePool) which
encapsulates all queues, keeps their references, instantiates it lazily and provides concurrency safety.

In order to avoid starving, QueuePool keeps track of the queue ("a last used queue") which prevents from
starving messages that were scheduled for the same time (basically a simple round-robin). QueuePool looks for a message
that is not scheduled to the future and can be executed (to do so we get O(N) where N is number of queues being used).

All workers listen on all queues for now. This prevents from waiting on a message that would be never processed.

In order to understand how Simulator works, you need to understand how Celery works. Please refer to Celery
documentation if you are a Celery-newbie.
"""

import logging
from datetime import datetime, timedelta
from flexmock import flexmock
from celery import Task as CeleryTask
from selinon import Config, run_flow
from selinon.systemState import SystemState
from selinonlib.globalConfig import GlobalConfig
from .celeryMocks import SimulateRetry, simulate_apply_async, simulate_retry, SimulateAsyncResult
from .queuePool import QueuePool
from .progress import Progress


class Simulator(object):
    """Simulator that simulates Selinon run in a multi-process environment"""
    simulator_queues = QueuePool()
    _logger = logging.getLogger(__name__)

    def __init__(self, nodes_definition, flow_definitions, **opts):
        """
        :param nodes_definition: path to nodes.yaml file
        :param flow_definitions: a list of YAML files describing flows
        :param opts: additional simulator options, supported: concurrency, config_py path, sleep_time, keep_config_py
        """
        Config.set_config_yaml(nodes_definition, flow_definitions,
                               config_py=opts.pop('config_py', None),
                               keep_config_py=opts.pop('keep_config_py', False))

        self.concurrency = opts.pop('concurrency', 1)
        self.sleep_time = opts.pop('sleep_time', 1)

        if opts:
            raise ValueError("Unknown options supplied: %s" % opts)

    def run(self, flow_name, node_args=None):
        """Run simulator

        :param flow_name: a flow name that should be run
        :param node_args: arguments for the flow
        """
        # We need to assing a custum async result as we are not running Celery but our mocks instead
        flexmock(SystemState, _get_async_result=SimulateAsyncResult)
        # Overwrite used Celery functions so we do not rely on Celery logic at all
        CeleryTask.apply_async = simulate_apply_async
        CeleryTask.retry = simulate_retry

        # Let's schedule the flow - our first starting task - task will be placed onto queue - see simulate_apply_async
        run_flow(flow_name, node_args)

        while not self.simulator_queues.is_empty():
            # TODO: concurrency
            self._logger.debug("new simulator run")

            # Retrieve a task that can be run right now
            time, record = self.simulator_queues.pop()
            task, celery_kwargs = record

            # we got a task with the lowest wait time - we need to wait if the task was scheduled in the future
            wait_time = (time - datetime.now()).total_seconds()
            Progress.sleep(wait_time=wait_time,
                           sleep_time=self.sleep_time,
                           info_text='Waiting for next task to process (%s seconds)... ' % round(wait_time, 3),
                           show_progressbar=self.concurrency == 1)
            try:
                kwargs = celery_kwargs.get('kwargs')
                # remove additional metadata placed by Selinon when doing tracing
                kwargs.pop('meta', None)
                result = task.run(**kwargs)

                # Dispatcher needs info about flow (JSON), but SelinonTaskEnvelope always returns None - we
                # need to keep track of success)
                SimulateAsyncResult.set_successful(task.request.id, result)
            except SimulateRetry as selinon_exc:
                if 'exc' in selinon_exc.celery_kwargs and selinon_exc.celery_kwargs.get('max_retries', 1) == 0:
                    # log only user exception as we do not want SimulateRetry in our exception traceback
                    user_exc = selinon_exc.celery_kwargs['exc']
                    self._logger.exception(str(user_exc), exc_info=(user_exc, user_exc, user_exc.__traceback__))
                    SimulateAsyncResult.set_failed(task.request.id, user_exc)
                else:
                    # reschedule if there was an exception and we did not hit max_retries when doing retry
                    Simulator.schedule(task, selinon_exc.celery_kwargs)
            except:
                raise RuntimeError("Ooooops! Congratulations! It looks like you've found a bug! Feel free to open an "
                                   "issue at https://github.com/selinon/selinonlib/issues")

    @classmethod
    def schedule(cls, task, celery_kwargs):
        """Schedule a new task to be executed

        :param task: task to be executed
        :type task: Dispatcher|SelinonTaskEnvelope
        :param celery_kwargs: arguments for the task - raw Celery arguments which also carry additional Selinon
                              arguments
        """
        cls._logger.debug("simulator is scheduling %s - %s", task.__class__.__name__, celery_kwargs)
        cls.simulator_queues.push(queue_name=celery_kwargs.get('queue', GlobalConfig.DEFAULT_CELERY_QUEUE),
                                  time=datetime.now() + timedelta(seconds=celery_kwargs.get('countdown') or 0),
                                  record=(task, celery_kwargs,))
