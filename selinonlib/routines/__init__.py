#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ######################################################################
# Copyright (C) 2016-2017  Fridolin Pokorny, fridolin.pokorny@gmail.com
# This file is part of Selinon project.
# ######################################################################

""" Supporting routines for run time """


def always_run(flow_name, task_name, node_args):  # pylint: disable=unused-argument
    """ Default function that is called on selective run """
    return {}
