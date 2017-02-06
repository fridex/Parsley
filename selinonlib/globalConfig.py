#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ######################################################################
# Copyright (C) 2016-2017  Fridolin Pokorny, fridolin.pokorny@gmail.com
# This file is part of Selinon project.
# ######################################################################
"""User's global configuration section parsed from YAML config file"""

from .helpers import check_conf_keys


class GlobalConfig(object):
    """
    User global configuration stated in YAML file
    """
    DEFAULT_CELERY_QUEUE = 'celery'
    predicates_module = 'selinonlib.predicates'

    default_task_queue = DEFAULT_CELERY_QUEUE
    default_dispatcher_queue = DEFAULT_CELERY_QUEUE

    _trace_logging = None
    _trace_import = None
    _trace_function = None
    _trace_storage = None

    def __init__(self):
        raise NotImplementedError("Cannot instantiate global config")

    @classmethod
    def dump_trace(cls, output, config_name, indent_count=0):
        """
        Dump trace configuration to output stream

        :param output: output stream to write to
        :param config_name: name of configuration class instance to be referenced when initializing trace
        :param indent_count: indentation that should be used to indent source
        """
        indent = indent_count * 4 * " "

        if cls._trace_logging:
            output.write('%s%s.trace_by_logging()\n' % (indent, config_name))
            return

        if cls._trace_storage:
            output.write('%s%s.trace_by_func(functools.partial(%s.%s, %s)\n'
                         % (indent, config_name, cls._trace_storage.class_name,
                            cls._trace_function, cls._trace_storage.var_name))

        if cls._trace_import:
            output.write('%sfrom %s import %s\n' % (indent, cls._trace_import, cls._trace_function))
            output.write('%s%s.trace_by_func(%s)\n' % (indent, config_name, cls._trace_function))

    @classmethod
    def _parse_trace(cls, system, trace_record):
        """
        Parse trace configuration entry

        @param system: system instance for which the parsing is done (for storage lookup)
        @param trace_record: trace record to be parsed
        """
        if trace_record is None:
            raise ValueError('Trace not defined properly in global configuration section')

        if trace_record is False:
            return

        if trace_record is True:
            cls._trace_logging = True
            return

        if 'storage' in trace_record:
            if 'method' in trace_record:
                cls._trace_function = trace_record['method']
            else:
                cls._trace_function = 'trace'

            storage = system.storage_by_name(trace_record['storage'])

            unknown_conf = check_conf_keys(trace_record, known_conf_opts=('method', 'storage'))
            if unknown_conf:
                raise ValueError("Unknown configuration for trace storage '%s' supplied: %s"
                                 % (trace_record['storage'], unknown_conf))

            cls._trace_storage = storage
        else:
            if 'import' not in trace_record:
                raise ValueError('Expected import definition if trace is not logging nor storage')

            if 'function' not in trace_record:
                raise ValueError('Expected function definition if trace is not logging nor storage')

            unknown_conf = check_conf_keys(trace_record, known_conf_opts=('import', 'function'))
            if unknown_conf:
                raise ValueError("Unknown configuration for trace function '%s' from '%s' supplied: %s"
                                 % (trace_record['function'], trace_record['import'], unknown_conf))

            cls._trace_import = trace_record['import']
            cls._trace_function = trace_record['function']

    @classmethod
    def from_dict(cls, system, dict_):
        """
        Parse global configuration from a dictionary

        :param system: system instance for storage lookup
        :param dict_: dictionary containing global configuration as stated in YAML config file
        """
        if 'predicates_module' in dict_:
            cls.predicates_module = dict_['predicates_module']

        if 'trace' in dict_:
            cls._parse_trace(system, dict_['trace'])

        cls.default_dispatcher_queue = dict_.get('default_dispatcher_queue', cls.DEFAULT_CELERY_QUEUE)
        cls.default_task_queue = dict_.get('default_task_queue', cls.DEFAULT_CELERY_QUEUE)

        unknown_conf = check_conf_keys(dict_, ('predicates_module', 'trace'))
        if unknown_conf:
            raise ValueError("Unknown configuration options supplied in global configuration section: %s"
                             % unknown_conf)
