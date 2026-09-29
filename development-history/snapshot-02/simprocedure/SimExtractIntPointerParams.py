#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Sep 18 20:02:31 2020

@author: ali
"""


class SimExtractIntPointerParams(angr.SimProcedure):
    def run(self,argc,argv):
        args=[]
        for i in self.arguments:
            addr=i.ast.args[0]
            args.append(self.state.mem[addr].int.concrete)
        self.state.globals=args
        self.exit(1)
        return 0
