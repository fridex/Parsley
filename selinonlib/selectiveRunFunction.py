#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ######################################################################
# Copyright (C) 2016-2017  Fridolin Pokorny, fridolin.pokorny@gmail.com
# This file is part of Selinon project.
# ######################################################################
""" Function that is run on selective flow/task run"""

from .helpers import check_conf_keys


class SelectiveRunFunction(object):
    """ Function that is run on selective flow/task run to ensure whether task/flow should be run """

    _DEFAULT_IMPORT_PATH = 'selinonlib.routines'
    _DEFAULT_FUNCTION_NAME = 'always_run'

    def __init__(self, name, import_path):
        self.name = name
        self.import_path = import_path

    @staticmethod
    def construct_import_name(name, import_path):
        """ Construct import name that will be used in generated config

        :param name: name of the function that will be imported
        :param import_path: import that should be used to import function
        :return: string representation of function that will be used in generated config
        """
        return "_{import_path}_{name}".format(import_path=import_path.replace(".", "_"), name=name)

    def get_import_name(self):
        """ Get import name that will be used in generated config

        :return: string representation of function that will be used in generated config
        """
        return self.construct_import_name(self.name, self.import_path)

    @classmethod
    def get_default(cls):
        """
        :return: default instance that will be used if user did not provided configuration
        """
        return cls(cls._DEFAULT_FUNCTION_NAME, cls._DEFAULT_IMPORT_PATH)

    @classmethod
    def from_dict(cls, dict_):
        """
        :return: selective run function that will be used based on configuration
        :rtype: SelectiveRunFunction
        """
        if not dict_:
            return cls.get_default()

        unknown_conf = check_conf_keys(dict_, known_conf_opts=('name', 'import'))
        if unknown_conf:
            raise ValueError("Unknown configuration options for selective run function supplied: %s"
                             % (unknown_conf.keys()))

        name = dict_.pop('name', cls._DEFAULT_FUNCTION_NAME)
        import_path = dict_.pop('import', cls._DEFAULT_IMPORT_PATH)

        return cls(name, import_path)
