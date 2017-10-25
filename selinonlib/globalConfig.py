#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ######################################################################
# Copyright (C) 2016-2017  Fridolin Pokorny, fridolin.pokorny@gmail.com
# This file is part of Selinon project.
# ######################################################################
"""User's global configuration section parsed from YAML config file."""

from .helpers import check_conf_keys


class GlobalConfig(object):
    """User global configuration stated in YAML file."""

    DEFAULT_CELERY_QUEUE = 'celery'
    predicates_module = 'selinonlib.predicates'

    default_task_queue = DEFAULT_CELERY_QUEUE
    default_dispatcher_queue = DEFAULT_CELERY_QUEUE

    _trace_logging = []
    _trace_function = []
    _trace_storage = []
    _trace_sentry = []

    def __init__(self):
        """Placeholder."""
        raise NotImplementedError("Cannot instantiate global config")

    @classmethod
    def dump_trace(cls, output, config_name, indent_count=0):
        """Dump trace configuration to output stream.

        :param output: output stream to write to
        :param config_name: name of configuration class instance to be referenced when initializing trace
        :param indent_count: indentation that should be used to indent source
        """
        indent = indent_count * 4 * " "

        for _ in cls._trace_logging:
            output.write('%s%s.trace_by_logging()\n' % (indent, config_name))

        for entry in cls._trace_storage:
            output.write('%s%s.trace_by_func(functools.partial(%s.%s, %s))\n'
                         % (indent, config_name, entry[0].class_name, entry[1], entry[0].var_name))

        for entry in cls._trace_function:
            output.write('%sfrom %s import %s\n' % (indent, entry[0], entry[1]))
            output.write('%s%s.trace_by_func(%s)\n' % (indent, config_name, entry[1]))

        for entry in cls._trace_sentry:
            output.write("%s%s.trace_by_sentry(dsn=%s)\n"
                         % (indent, config_name, "'%s'" % entry if entry is not True else None))

    @classmethod
    def _parse_trace_storage(cls, trace_def, system):
        """Parse tracing by storage.

        :param trace_def: definition of tracing as supplied in the YAML file
        :param system: system instance
        """
        if not isinstance(trace_def, dict):
            raise ValueError("Configuration of storage trace expects dict, got '%s' instead (type: %s)"
                             % (trace_def, type(trace_def)))

        if 'name' not in trace_def:
            raise ValueError('Expected storage name in tracing configuration, got %s instead'
                             % trace_def)

        unknown_conf = check_conf_keys(trace_def, known_conf_opts=('method', 'name'))
        if unknown_conf:
            raise ValueError("Unknown configuration for trace storage '%s' supplied: %s"
                             % (trace_def, unknown_conf))

        cls._trace_storage.append((system.storage_by_name(trace_def['name']), trace_def.get('method', 'trace')))

    @classmethod
    def _parse_trace_function(cls, trace_def):
        """Parse tracing by external function.

        :param trace_def: definition of tracing as supplied in the YAML file
        """
        if not isinstance(trace_def, dict):
            raise ValueError("Configuration of trace function expects dict, got '%s' instead (type: %s)"
                             % (trace_def, type(trace_def)))

        if 'import' not in trace_def:
            raise ValueError('Expected import definition in function trace configuration, got %s instead'
                             % trace_def)

        if 'name' not in trace_def:
            raise ValueError('Expected function name in function trace configuration, got %s instead'
                             % trace_def)

        unknown_conf = check_conf_keys(trace_def, known_conf_opts=('import', 'name'))
        if unknown_conf:
            raise ValueError("Unknown configuration for trace function '%s' from '%s' supplied: %s"
                             % (trace_def['name'], trace_def['import'], unknown_conf))

        cls._trace_function.append((trace_def['import'], trace_def['name']))

    @classmethod
    def _parse_trace_logging(cls, trace_def):
        """Parse tracing by Python's logging facilities.

        :param trace_def: definition of tracing as supplied in the YAML file
        """
        if trace_def is True:
            cls._trace_logging.append(trace_def)

    @classmethod
    def _parse_trace_sentry(cls, trace_def):
        """Parse tracing by Sentry - error tracking software.

        :param trace_def: definition of tracing as supplied in the YAML file
        """
        if not isinstance(trace_def, dict):
            raise ValueError("Configuration of Sentry tracing expects dict, got '%s' instead (type: %s)"
                             % (trace_def, type(trace_def)))

        unknown_conf = check_conf_keys(trace_def, known_conf_opts=('dsn',))
        if unknown_conf:
            raise ValueError("Unknown configuration for Sentry trace function supplied: %s" % unknown_conf)

        cls._trace_sentry.append(trace_def.get('dsn', True))

    @classmethod
    def _parse_trace(cls, system, trace_record):
        """Parse trace configuration entry.

        :param system: system instance for which the parsing is done (for storage lookup)
        :param trace_record: trace record to be parsed
        """
        if trace_record is None:
            raise ValueError('Trace not defined properly in global configuration section, '
                             'see documentation for more info')

        if trace_record is False:
            return

        trace_record = [trace_record] if not isinstance(trace_record, list) else trace_record

        for entry in trace_record:
            if 'logging' in entry:
                cls._parse_trace_logging(entry['logging'])

            if 'storage' in entry:
                cls._parse_trace_storage(entry['storage'], system)

            if 'function' in entry:
                cls._parse_trace_function(entry['function'])

            if 'sentry' in entry:
                cls._parse_trace_sentry(entry['sentry'])

    @classmethod
    def from_dict(cls, system, dict_):
        """Parse global configuration from a dictionary.

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
