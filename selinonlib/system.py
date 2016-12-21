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
"""Core Selinonlib logic - system representation, parsing and hanling actions"""

import os
import datetime
import platform
import logging
import codegen
import graphviz
import yaml
from .task import Task
from .storage import Storage
from .flow import Flow
from .version import selinonlib_version
from .config import Config
from .helpers import dict2strkwargs, expr2str
from .taskClass import TaskClass
from .globalConfig import GlobalConfig

# pylint: disable=too-many-locals,too-many-nested-blocks,too-many-boolean-expressions


class System(object):
    """
    The representation of the whole system
    """

    _logger = logging.getLogger(__name__)

    def __init__(self, tasks=None, flows=None, storages=None, task_classes=None):
        """
        :param tasks: a list of tasks available in the system
        :param flows: a list of flows available in the system
        :param storages: a list of storages available in the system
        :param task_classes: a list of classes that implement task logic (the same Python class can be represented
                             in multiple Selinon tasks)
        """
        self.flows = flows or []
        self.tasks = tasks or []
        self.storages = storages or []
        self.task_classes = task_classes or []

    def _check_name_collision(self, name):
        """
        Tasks and Flows share name space, check for collisions

        :param name: a node name
        :raises: ValueError
        """
        if any(flow.name == name for flow in self.flows):
            raise ValueError("Unable to add node with name '%s', a flow with the same name already exist" % name)
        if any(task.name == name for task in self.tasks):
            raise ValueError("Unable to add node with name '%s', a task with the same name already exist" % name)

    def add_task(self, task):
        """
        Register a task in the system

        :param task: a task to be registered
        :type task: Task
        """
        self._check_name_collision(task.name)
        self.tasks.append(task)

    def add_flow(self, flow):
        """
        Register a flow in the system

        :param flow: a flow to be registered
        :type flow: flow
        """
        self._check_name_collision(flow.name)
        self.flows.append(flow)

    def add_storage(self, storage):
        """
        Add storage to system

        :param storage: storage that should be added
        """
        # We need to check for name collision with tasks as well since we import them by name
        for task in self.tasks:
            if task.name == storage.name:
                raise ValueError("Storage has same name as task '%s'" % storage.name)

        for stored_storage in self.storages:
            if stored_storage.name == storage:
                raise ValueError("Multiple storages of the same name '{}'".format(storage.name))
        self.storages.append(storage)

    def storage_by_name(self, name, graceful=False):
        """
        Retrieve storage by its name

        :param name: name of the storage
        :param graceful: if true, exception is raised if no such storage with name name is found
        :return: storage
        """
        for storage in self.storages:
            if storage.name == name:
                return storage
        if not graceful:
            raise KeyError("Storage with name {} not found in the system".format(name))
        return None

    def task_by_name(self, name, graceful=False):
        """
        Find a task by its name

        :param name: a task name
        :param graceful: if True, no exception is raised if task couldn't be found
        :return: task with name 'name'
        :rtype: Task
        :raises: KeyError
        """
        for task in self.tasks:
            if task.name == name:
                return task
        if not graceful:
            raise KeyError("Task with name {} not found in the system".format(name))
        return None

    def task_queue_names(self):
        """
        :return: corresponding mapping from task name to task queue
        """
        ret = {}

        for task in self.tasks:
            ret[task.name] = task.queue_name

        return ret

    def dispatcher_queue_names(self):
        """
        :return: dispatcher queue name
        """
        ret = {}

        for flow in self.flows:
            ret[flow.name] = flow.queue_name

        return ret

    def flow_by_name(self, name, graceful=False):
        """
        Find a flow by its name

        :param name: a flow name
        :param graceful: if True, no exception is raised if flow couldn't be found
        :return: flow with name 'name'
        :rtype: Flow
        :raises: KeyError
        """
        for flow in self.flows:
            if flow.name == name:
                return flow
        if not graceful:
            raise KeyError("Flow with name '{}' not found in the system".format(name))
        return None

    def node_by_name(self, name, graceful=False):
        """
        Find a node (flow or task) by its name

        :param name: a node name
        :param graceful: if True, no exception is raised if node couldn't be found
        :return: flow with name 'name'
        :rtype: Node
        :raises: KeyError
        """
        node = self.task_by_name(name, graceful=True)

        if not node:
            node = self.flow_by_name(name, graceful=True)

        if not node and not graceful:
            raise KeyError("Entity with name '{}' not found in the system".format(name))

        return node

    def class_of_task(self, task):
        """
        Return task class of a task

        :param task: task to look task class for
        :return: TaskClass or None if a task class for task is not available
        """
        for task_class in self.task_classes:
            if task_class.task_of_class(task):
                return task_class
        return None

    def _dump_imports(self, output):
        """
        Dump used imports of tasks to a stream

        :param output: a stream to write to
        """
        predicates = set([])
        for flow in self.flows:
            for edge in flow.edges:
                predicates.update([p.__name__ for p in edge.predicate.predicates_used()])
        if predicates:
            output.write('from %s import %s\n' % (GlobalConfig.predicates_module, ", ".join(predicates)))

        for flow in self.flows:
            for idx, edge in enumerate(flow.edges):
                if edge.foreach:
                    output.write('from {} import {} as {}\n'.format(edge.foreach['import'],
                                                                    edge.foreach['function'],
                                                                    self._dump_foreach_function_name(flow.name, idx)))
        for task in self.tasks:
            output.write("from {} import {} as {}\n".format(task.import_path, task.class_name, task.name))

        for storage in self.storages:
            if len(storage.tasks) > 0:
                output.write("from {} import {}\n".format(storage.import_path, storage.class_name))

                cache_config = storage.cache_config
                output.write("from {} import {}".format(cache_config.import_path,
                                                        cache_config.name))

        # we need partial for strategy function and for using storage as trace destination
        output.write("\nimport functools\n")
        # we need datetime for timedelta in throttle
        output.write("\nimport datetime\n")

    def _dump_output_schemas(self, output):
        """
        Dump output schema mapping to a stream

        :param output: a stream to write to
        """
        output.write('output_schemas = {')
        printed = False
        for task in self.tasks:
            if task.output_schema:
                if printed:
                    output.write(",")
                output.write("\n    '%s': '%s'" % (task.name, task.output_schema))
                printed = True
        output.write('\n}\n\n')

    def _dump_flow_flags(self, stream):
        """
        Dump various flow flags

        :param stream: a stream to write to
        """
        self._dump_dict(stream,
                        'node_args_from_first',
                        [{f.name: f.node_args_from_first} for f in self.flows])

        self._dump_dict(stream,
                        'propagate_node_args',
                        [{f.name: f.propagate_node_args} for f in self.flows])

        self._dump_dict(stream,
                        'propagate_finished',
                        [{f.name: f.propagate_finished} for f in self.flows])

        self._dump_dict(stream,
                        'propagate_parent',
                        [{f.name: f.propagate_parent} for f in self.flows])

        self._dump_dict(stream,
                        'propagate_compound_finished',
                        [{f.name: f.propagate_compound_finished} for f in self.flows])

    @staticmethod
    def _dump_dict(output, dict_name, dict_items):
        """
        Dump propagate_finished flag configuration to a stream

        :param output: a stream to write to
        """
        output.write('%s = {' % dict_name)
        printed = False
        for item in dict_items:
            for key, value in item.items():
                if printed:
                    output.write(",")
                if isinstance(value, list):
                    string = [item.name for item in value]
                else:
                    string = str(value)
                output.write("\n    '%s': %s" % (key, string))
                printed = True
        output.write('\n}\n\n')

    def _dump_task_classes(self, output):
        """
        Dump mapping from task name to task class

        :param output: a stream to write to
        """
        output.write('task_classes = {')
        printed = False
        for task in self.tasks:
            if printed:
                output.write(',')
            output.write("\n    '%s': %s" % (task.name, task.name))
            printed = True
        output.write('\n}\n\n')

    def _dump_storage_task_names(self, output):
        """
        Dump mapping for task name in storage (task name alias for storage)

        :param output: a stream to write to
        """
        output.write('storage_task_name = {')
        printed = False
        for task in self.tasks:
            if printed:
                output.write(',')
            output.write("\n    '%s': '%s'" % (task.name, task.storage_task_name))
            printed = True
        output.write('\n}\n\n')

    def _dump_queues(self, output):
        """
        Dump queues for tasks and dispatcher

        :param output: a stream to write to
        """
        self._dump_dict(output, 'task_queues', [{f.name: "'%s'" % f.queue_name} for f in self.tasks])
        self._dump_dict(output, 'dispatcher_queues', [{f.name: "'%s'" % f.queue_name} for f in self.flows])

    def _dump_storage2instance_mapping(self, output):
        """
        Dump storage name to instance mapping to a stream

        :param output: a stream to write to
        """
        storage_var_names = []
        for storage in self.storages:
            if len(storage.tasks) > 0:
                output.write("%s = %s" % (storage.var_name, storage.class_name))
                if storage.configuration and isinstance(storage.configuration, dict):
                    output.write("(%s)\n" % dict2strkwargs(storage.configuration))
                elif storage.configuration:
                    output.write("(%s)\n" % expr2str(storage.configuration))
                else:
                    output.write("()\n")

                storage_var_names.append((storage.name, storage.var_name,))

        output.write('storage2instance_mapping = {\n')
        printed = False
        for storage_var_name in storage_var_names:
            if printed:
                output.write(",\n")
            output.write("    '%s': %s" % (storage_var_name[0], storage_var_name[1]))
            printed = True

        output.write("\n}\n\n")

    def _dump_task2storage_mapping(self, output):
        """
        Dump task name to storage name mapping to a stream

        :param output: a stream to write to
        """
        output.write('task2storage_mapping = {\n')
        printed = False
        for task in self.tasks:
            if printed:
                output.write(",\n")
            storage_name = ("'%s'" % task.storage.name) if task.storage else str(None)
            output.write("    '%s': %s" % (task.name, storage_name))
            printed = True

        output.write("\n}\n\n")

    def _dump_storage_conf(self, output):
        """
        Dump storage configuration to a stream

        :param output: a stream to write to
        """
        self._dump_task2storage_mapping(output)
        self._dump_storage2instance_mapping(output)
        for storage in self.storages:
            cache_config = storage.cache_config
            output.write("%s = %s(%s)\n" % (cache_config.var_name, cache_config.name,
                                            dict2strkwargs(cache_config.options)))
        self._dump_dict(output, 'storage2storage_cache', [{s.name: s.cache_config.var_name for s in self.storages}])

    def _dump_strategy_func(self, output):
        """
        Dump scheduling strategy function to a stream

        :param output: a stream to write to
        """
        def strategy_func_name(flow):  # pylint: disable=missing-docstring
            return "_strategy_func_%s" % flow.name

        def strategy_func_import_name(flow):  # pylint: disable=missing-docstring
            return "_raw_strategy_func_%s" % flow.name

        strategy_dict = {}
        for flow in self.flows:
            output.write("from %s import %s as %s\n"
                         % (flow.strategy.module, flow.strategy.function, strategy_func_import_name(flow)))
            output.write('%s = functools.partial(%s, %s)\n\n'
                         % (strategy_func_name(flow),
                            strategy_func_import_name(flow),
                            dict2strkwargs(flow.strategy.func_args)))
            strategy_dict[flow.name] = strategy_func_name(flow)

        output.write('\n')
        self._dump_dict(output, 'strategies', [strategy_dict])

    @staticmethod
    def _dump_condition_name(flow_name, idx):
        """
        Create condition name for a dump

        :param flow_name: flow name
        :type flow_name: str
        :param idx: index of condition within the flow
        :type idx: int
        :return: condition function representation
        """
        assert idx >= 0
        return '_condition_{}_{}'.format(flow_name, idx)

    @staticmethod
    def _dump_foreach_function_name(flow_name, idx):
        """
        Create foreach function name for a dump

        :param flow_name: flow name
        :type flow_name: str
        :param idx: index of condition within the flow
        :type idx: int
        :return: condition function representation
        """
        assert idx >= 0
        return '_foreach_{}_{}'.format(flow_name, idx)

    def _dump_condition_functions(self, output):
        """
        Dump condition functions to a stream

        :param output: a stream to write to
        """
        for flow in self.flows:
            for idx, edge in enumerate(flow.edges):
                output.write('def {}(db, node_args):\n'.format(self._dump_condition_name(flow.name, idx)))
                output.write('    return {}\n\n\n'.format(codegen.to_source(edge.predicate.ast())))

    def _dump_throttle(self, output):
        """
        Dump throttle configuration

        :param output: a stream to write to
        """
        self._dump_dict(output, 'throttle_tasks', [{t.name: repr(t.throttle)} for t in self.tasks])
        self._dump_dict(output, 'throttle_flows', [{f.name: repr(f.throttle)} for f in self.flows])

    def _dump_max_retry(self, output):
        """
        Dump max_retry configuration to a stream

        :param output: a stream to write to
        """
        output.write('max_retry = {')
        printed = False
        for task in self.tasks:
            if printed:
                output.write(',')
            output.write("\n    '%s': %d" % (task.name, task.max_retry))
            printed = True
        output.write('\n}\n\n')

    def _dump_retry_countdown(self, output):
        """
        Dump retry_countdown configuration to a stream

        :param output: a stream to write to
        """
        output.write('retry_countdown = {')
        printed = False
        for task in self.tasks:
            if printed:
                output.write(',')
            output.write("\n    '%s': %d" % (task.name, task.retry_countdown))
            printed = True
        output.write('\n}\n\n')

    def _dump_storage_readonly(self, output):
        """
        Dump storage_readonly flow to a stream

        :param output: a stream to write to
        """
        output.write('storage_readonly = {')
        printed = False
        for task in self.tasks:
            if printed:
                output.write(',')
            output.write("\n    '%s': %s" % (task.name, task.storage_readonly))
            printed = True
        output.write('\n}\n\n')

    def _dump_nowait_nodes(self, output):
        """
        Dump nowait nodes to a stream

        :param output: a stream to write to
        """

        output.write('nowait_nodes = {\n')
        printed = False
        for flow in self.flows:
            if printed:
                output.write(',\n')
            output.write("    '%s': %s" % (flow.name, [node.name for node in flow.nowait_nodes]))
            printed = True

        output.write('\n}\n\n')

    @staticmethod
    def _dump_init(output):
        """
        Dump init function to a stream

        :param output: a stream to write to
        :return:
        """
        output.write('def init(config_cls):\n')
        GlobalConfig.dump_trace(output, 'config_cls', indent_count=1)
        # always pass in case we have nothing to init
        output.write('    return\n')
        output.write('\n')

    def _dump_edge_table(self, output):
        """
        Dump edge definition table to a stream

        :param output: a stream to write to
        """
        output.write('edge_table = {\n')
        for idx, flow in enumerate(self.flows):
            output.write("    '{}': [".format(flow.name))
            for idx_edge, edge in enumerate(flow.edges):
                if idx_edge > 0:
                    output.write(',\n')
                    output.write(' '*(len(flow.name) + 4 + 5)) # align to previous line
                output.write("{'from': %s" % str([node.name for node in edge.nodes_from]))
                output.write(", 'to': %s" % str([node.name for node in edge.nodes_to]))
                output.write(", 'condition': %s" % self._dump_condition_name(flow.name, idx_edge))
                output.write(", 'condition_str': '%s'" % str(edge.predicate).replace('\'', '\\\''))
                if edge.foreach:
                    output.write(", 'foreach': %s" % self._dump_foreach_function_name(flow.name, idx_edge))
                    output.write(", 'foreach_str': '%s'" % edge.foreach_str())
                    output.write(", 'foreach_propagate_result': %s" % edge.foreach['propagate_result'])
                output.write("}")
            if idx + 1 < len(self.flows):
                output.write('],\n')
            else:
                output.write(']\n')
        output.write('}\n\n')

    def dump2stream(self, stream):
        """
        Perform system dump to a Python source code to an output stream

        :param stream: an output stream to write to
        """
        stream.write('#!/usr/bin/env python3\n')
        stream.write('# auto-generated using Selinonlib v{} on {} at {}\n\n'.format(selinonlib_version,
                                                                                    platform.node(),
                                                                                    str(datetime.datetime.utcnow())))
        self._dump_imports(stream)
        self._dump_strategy_func(stream)
        self._dump_task_classes(stream)
        self._dump_storage_task_names(stream)
        self._dump_queues(stream)
        stream.write('#'*80+'\n\n')
        self._dump_storage_conf(stream)
        stream.write('#'*80+'\n\n')
        self._dump_output_schemas(stream)
        stream.write('#'*80+'\n\n')
        self._dump_flow_flags(stream)
        self._dump_throttle(stream)
        stream.write('#'*80+'\n\n')
        self._dump_max_retry(stream)
        self._dump_retry_countdown(stream)
        self._dump_storage_readonly(stream)
        stream.write('#'*80+'\n\n')

        for flow in self.flows:
            if flow.failures:
                flow.failures.dump2stream(stream, flow.name)

        stream.write('failures = {')
        printed = False
        for flow in self.flows:
            if flow.failures:
                if printed:
                    stream.write(",")
                printed = True
                stream.write("\n    '%s': %s" % (flow.name, flow.failures.starting_nodes_name(flow.name)))
        stream.write('\n}\n\n')

        stream.write('#'*80+'\n\n')
        self._dump_nowait_nodes(stream)
        stream.write('#'*80+'\n\n')
        self._dump_init(stream)
        stream.write('#'*80+'\n\n')
        self._dump_condition_functions(stream)
        stream.write('#'*80+'\n\n')
        self._dump_edge_table(stream)
        stream.write('#'*80+'\n\n')

    def dump2file(self, output_file):
        """
        Perform system dump to a Python source code

        :param output_file: an output file to write to
        """
        self._logger.debug("Performing system dump to '%s'", output_file)
        with open(output_file, 'w') as stream:
            self.dump2stream(stream)

    def plot_graph(self, output_dir, image_format=None):  # pylint: disable=too-many-statements,too-many-branches
        """
        Plot system flows to graphs - each flow in a separate file

        :param output_dir: output directory to write graphs of flows to
        :param image_format: image format, the default is svg if None
        :return: list of file names to which the graph was rendered
        :rtype: List[str]
        """
        # TODO: this method needs to be refactored
        self._logger.debug("Rendering system flows to '%s'", output_dir)
        ret = []
        image_format = image_format if image_format else 'svg'

        for flow in self.flows:
            storage_connections = []
            graph = graphviz.Digraph(format=image_format)
            graph.graph_attr.update(Config().style_graph())
            graph.node_attr.update(Config().style_task())
            graph.edge_attr.update(Config().style_edge())

            for idx, edge in enumerate(flow.edges):
                condition_node = "%s_%s" % (flow.name, idx)
                if edge.foreach:
                    condition_label = "%s\n%s" % (str(edge.predicate), edge.foreach_str())
                    graph.node(name=condition_node, label=condition_label,
                               _attributes=Config().style_condition_foreach())
                else:
                    graph.node(name=condition_node, label=str(edge.predicate),
                               _attributes=Config().style_condition())

                for node in edge.nodes_to:
                    # Plot storage connection
                    if node.is_flow():
                        graph.node(name=node.name, _attributes=Config().style_flow())
                    else:
                        graph.node(name=node.name)
                        if node.storage:
                            graph.node(name=node.storage.name, _attributes=Config().style_storage())
                            if (node.name, node.storage.name) not in storage_connections:
                                graph.edge(node.name, node.storage.name, _attributes=Config().style_store_edge())
                                storage_connections.append((node.name, node.storage.name,))
                    graph.edge(condition_node, node.name)
                for node in edge.nodes_from:
                    if node.is_flow():
                        graph.node(name=node.name, _attributes=Config().style_flow())
                    else:
                        graph.node(name=node.name)
                        if node.storage:
                            graph.node(name=node.storage.name, _attributes=Config().style_storage())
                            if (node.name, node.storage.name) not in storage_connections:
                                graph.edge(node.name, node.storage.name, _attributes=Config().style_store_edge())
                                storage_connections.append((node.name, node.storage.name,))
                    graph.edge(node.name, condition_node)

            # Plot failures as well
            if flow.failures:
                for failure in flow.failures.raw_definition:
                    if len(failure['nodes']) == 1 and \
                            (isinstance(failure['fallback'], bool) or len(failure['fallback']) == 1):
                        graph.node(name=failure['nodes'][0])

                        if isinstance(failure['fallback'], list):
                            fallback_node_name = failure['fallback'][0]
                        else:
                            fallback_node_name = str(failure['fallback'])

                        graph.node(name=fallback_node_name)
                        graph.edge(failure['nodes'][0], fallback_node_name,
                                   _attributes=Config().style_fallback_edge())

                        if not isinstance(failure['fallback'], bool):
                            node = self.node_by_name(failure['fallback'][0])
                            if node.is_task() and node.storage:
                                graph.node(name=node.storage.name, _attributes=Config().style_storage())
                                if (node.name, node.storage.name) not in storage_connections:
                                    graph.edge(node.name, node.storage.name, _attributes=Config().style_store_edge())
                                    storage_connections.append((node.name, node.storage.name,))
                    else:
                        graph.node(name=str(id(failure)), _attributes=Config().style_fallback_node())

                        for node_name in failure['nodes']:
                            if self.node_by_name(node_name).is_flow():
                                graph.node(name=node_name, _attributes=Config().style_flow())
                            else:
                                graph.node(name=node_name)
                            graph.edge(node_name, str(id(failure)), _attributes=Config().style_fallback_edge())

                        if failure['fallback'] is True:
                            graph.node(name=str(id(failure['fallback'])), label="True",
                                       _attributes=Config().style_fallback_true())
                            graph.edge(str(id(failure)), str(id(failure['fallback'])),
                                       _attributes=Config().style_fallback_edge())
                        else:
                            for node_name in failure['fallback']:
                                node = self.node_by_name(node_name)
                                if node.is_flow():
                                    graph.node(name=node.name, _attributes=Config().style_flow())
                                else:
                                    graph.node(name=node.name)
                                    if node.storage:
                                        graph.node(name=node.storage.name, _attributes=Config().style_storage())
                                        if (node.name, node.storage.name) not in storage_connections:
                                            graph.edge(node.name,
                                                       node.storage.name,
                                                       _attributes=Config().style_store_edge())
                                            storage_connections.append((node.name, node.storage.name,))

                                graph.edge(str(id(failure)), node_name, _attributes=Config().style_fallback_edge())

            file = os.path.join(output_dir, "%s" % flow.name)
            graph.render(filename=file, cleanup=True)
            ret.append(file)
            self._logger.info("Graph rendered to '%s.%s'", file, image_format)

        return ret

    def _post_parse_check(self):
        """
        Called once parse was done to ensure that system was correctly defined in config file

        :raises: ValueError
        """
        self._logger.debug("Post parse check is going to be executed")
        # we want to have circular dependencies, so we need to check consistency after parsing since all flows
        # are listed (by names) in a separate definition
        for flow in self.flows:
            if len(flow.edges) == 0:
                raise ValueError("Empty flow: %s" % flow.name)

    def _check(self):  # pylint: disable=too-many-statements,too-many-branches
        """
        Check system for consistency

        :raises: ValueError
        """
        self._logger.info("Checking system for consistency")

        for task_class in self.task_classes:
            task_ref = task_class.tasks[0]
            for task in task_class.tasks[1:]:
                if task_ref.output_schema != task.output_schema:
                    self._logger.warning("Different output schemas to a same task class: %s and %s for class '%s', "
                                         "schemas: '%s' and '%s' might differ",
                                         task_ref.name, task.name, task_class.class_name,
                                         task_ref.output_schema, task.output_schema)

                if task.max_retry != task_ref.max_retry:
                    self._logger.warning("Different max_retry assigned to a same task class: %s and %s for class '%s'",
                                         (task.name, task.max_retry), (task_ref.name, task_ref.max_retry),
                                         task_class.class_name)

        for storage in self.storages:
            if len(storage.tasks) == 0:
                self._logger.warning("Storage '%s' not used in any flow", storage.name)

        # We want to check that if we depend on a node, that node is being started at least once in the flow
        # This also covers check for starting node definition
        for flow in self.flows:
            # TODO: we should make this more transparent by placing it to separate functions
            try:
                all_source_nodes = flow.all_source_nodes()
                all_destination_nodes = flow.all_destination_nodes()

                starting_edges_count = 0
                starting_nodes_count = 0

                for edge in flow.edges:
                    edge.check()

                    if len(edge.nodes_from) == 0:
                        starting_edges_count += 1
                        starting_nodes_count += len(edge.nodes_to)

                        if flow.node_args_from_first:
                            if len(edge.nodes_to) > 1:
                                raise ValueError("Cannot propagate node arguments from multiple starting nodes")

                            if edge.nodes_to[0].is_flow():
                                raise ValueError("Cannot propagate node arguments from a sub-flow")

                    node_seen = {}
                    for node_from in edge.nodes_from:
                        if not node_seen.get(node_from.name, False):
                            node_seen[node_from.name] = True
                        else:
                            raise ValueError("Nodes cannot be dependent on a node of a same type mode than once; "
                                             "node from '%s' more than once in flow '%s'" % (node_from.name, flow.name))

                    edge.predicate.check()

                if starting_edges_count > 1:
                    self._logger.warning("Multiple starting nodes defined in flow '%s'", flow.name)

                    if flow.node_args_from_first:
                        raise ValueError("Cannot propagate node arguments from multiple starting nodes")

                if starting_nodes_count == 0:
                    raise ValueError("No starting node found in flow '%s'" % flow.name)

                for nowait_node in flow.nowait_nodes:
                    if nowait_node in all_source_nodes:
                        raise ValueError("Node '%s' marked as 'nowait' but dependency in the flow found"
                                         % nowait_node.name)

                if isinstance(flow.propagate_finished, list):
                    for node in flow.propagate_finished:
                        if node not in all_source_nodes:
                            raise ValueError("Subflow '%s' should receive parent nodes, but there is no dependency "
                                             "in flow '%s' to which should be parent nodes propagated"
                                             % (node.name, flow.name))

                        # propagate_finished set to a flow but these arguments are not passed due
                        # to propagate_parent
                        if node.is_flow():
                            affected_edges = [edge for edge in flow.edges if node in edge.nodes_from]
                            for affected_edge in affected_edges:
                                f = [n for n in affected_edge.nodes_to if n.is_flow()]  # pylint: disable=invalid-name
                                if len(f) == 1 and not flow.should_propagate_parent(f[0]):
                                    self._logger.warning("Flow '%s' marked in propagate_finished, but calculated "
                                                         "finished nodes are not passed to sub-flow '%s' due to not "
                                                         "propagating parent, in flow '%s'",
                                                         node.name, f[0].name, flow.name)

                if isinstance(flow.propagate_compound_finished, list):
                    for node in flow.propagate_compound_finished:
                        if node not in all_source_nodes:
                            raise ValueError("Subflow '%s' should receive parent nodes, but there is no dependency "
                                             "in flow '%s' to which should be parent nodes propagated"
                                             % (node.name, flow.name))

                        # propagate_compound_finished set to a flow but these arguments are not passed due
                        # to propagate_parent
                        if node.is_flow():
                            affected_edges = [edge for edge in flow.edges if node in edge.nodes_from]
                            for affected_edge in affected_edges:
                                f = [n for n in affected_edge.nodes_to if n.is_flow()]  # pylint: disable=invalid-name
                                if len(f) == 1 and not flow.should_propagate_parent(f[0]):
                                    self._logger.warning("Flow '%s' marked in propagate_compound_finished, but "
                                                         "calculated finished nodes are not passed to sub-flow '%s' "
                                                         "due to not propagating parent, in flow '%s'",
                                                         node.name, f[0].name, flow.name)

                if isinstance(flow.propagate_parent, list):
                    for node in flow.propagate_parent:
                        if node not in all_source_nodes:
                            raise ValueError("Subflow '%s' should receive parent, but there is no dependency "
                                             "in flow '%s' to which should be parent nodes propagated"
                                             % (node.name, flow.name))

                if isinstance(flow.propagate_finished, list) and isinstance(flow.propagate_compound_finished, list):
                    for node in flow.propagate_finished:
                        if node in flow.propagate_compound_finished:
                            raise ValueError("Cannot mark node '%s' for propagate_finished and "
                                             "propagate_compound_finished at the same time in flow '%s'"
                                             % (node.name, flow.name))
                else:
                    if (flow.propagate_finished is True and flow.propagate_compound_finished is True)  \
                          or (flow.propagate_finished is True and isinstance(flow.propagate_compound_finished, list)) \
                          or (isinstance(flow.propagate_finished, list) and flow.propagate_compound_finished is True):
                        raise ValueError("Flags propagate_compound_finished and propagate_finished are disjoint,"
                                         " please specify configuration for each node separately in flow '%s'"
                                         % flow.name)

                not_started = list(set(all_source_nodes) - set(all_destination_nodes))

                error = False
                for node in not_started:
                    if node.is_task():
                        self._logger.error("Dependency in flow '%s' on node '%s', but this node is not started "
                                           "in the flow", flow.name, node.name)
                        error = True

                if error:
                    raise ValueError("Dependency on not started node detected in flow '%s'" % flow.name)
            except:
                self._logger.error("Check of flow '%s' failed", flow.name)
                raise

    @classmethod
    def from_files(cls, nodes_definition_file, flow_definition_files, no_check=False):
        """
        Construct System from files

        :param nodes_definition_file: path to nodes definition file
        :param flow_definition_files: path to files that describe flows
        :param no_check: True if system shouldn't be checked for consistency (recommended to check)
        :return: System instance
        :rtype: System
        """
        system = System()

        with open(nodes_definition_file, 'r') as nodes_file:
            cls._logger.debug("Parsing '%s'", nodes_definition_file)
            try:
                content = yaml.load(nodes_file, Loader=yaml.SafeLoader)
            except:
                cls._logger.error("Bad YAML file, unable to load tasks from '%s'", nodes_definition_file)
                raise

        for storage_dict in content.get('storages', []):
            storage = Storage.from_dict(storage_dict)
            system.add_storage(storage)

        if 'global' in content:
            GlobalConfig.from_dict(system, content['global'])

        if 'tasks' not in content or content['tasks'] is None:
            raise ValueError("No tasks defined in the system")

        for task_dict in content['tasks']:
            task = Task.from_dict(task_dict, system)
            task_class = system.class_of_task(task)
            if not task_class:
                task_class = TaskClass(task.class_name, task.import_path)
                system.task_classes.append(task_class)
            task_class.add_task(task)
            task.task_class = task_class
            system.add_task(task)

        for flow_name in content['flows']:
            flow = Flow(flow_name)
            system.add_flow(flow)

        if not isinstance(flow_definition_files, list):
            flow_definition_files = [flow_definition_files]

        for flow_file in flow_definition_files:
            with open(flow_file, 'r') as flow_definition:
                cls._logger.debug("Parsing '%s'", flow_file)
                try:
                    content = yaml.load(flow_definition, Loader=yaml.SafeLoader)
                except:
                    cls._logger.error("Bad YAML file, unable to load flow from '%s'", flow_file)
                    raise

            for flow_def in content['flow-definitions']:
                flow = system.flow_by_name(flow_def['name'])
                flow.parse_definition(flow_def, system)

        system._post_parse_check()  # pylint: disable=protected-access
        if not no_check:
            system._check()  # pylint: disable=protected-access

        return system
