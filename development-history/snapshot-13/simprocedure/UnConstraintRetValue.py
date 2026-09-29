#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu May 27 18:56:44 2021

@author: ali
"""

import angr,claripy


class ExeFunc(angr.SimProcedure):
    def run(*argv):
        return claripy.BVS('UNEXFUN',8)