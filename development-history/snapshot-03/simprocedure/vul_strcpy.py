#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jan 10 12:28:30 2021

@author: ali
"""


class _strcpy_vul(angr.SimProcedure): 
    def run(self,dst,src,call_sites=None): 
        tcpy=angr.SIM_PROCEDURES['libc']['strcpy'] 
        re = self.inline_call(tcpy,dst,src).ret_expr 
        mem_src=self.state.memory.load(src,1)
        mem_dst=self.state.memory.load(dst,1)
        
        sz=-1
        active=call_sites.pop(0)
          
        if len(mem_src.args) > 2:
            sz=mem_src.args[2].size() 
            sz=int(sz/8)
            self.state.globals[active]=self.state.memory.load(src,sz)
        else:
            value=self.state.mem[src.to_claripy()].string.concrete
            self.state.globals[active]=value.decode()

        return re
