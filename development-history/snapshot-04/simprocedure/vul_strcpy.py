#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jan 10 12:28:30 2021

@author: ali
"""


class _strcpy_vul(angr.SimProcedure): 
    def run(self,dst_addr, src_addr,call_sites=None): 
        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        memcpy = angr.SIM_PROCEDURES['libc']['memcpy']
        
        src_len = self.inline_call(strlen, src_addr).ret_expr
        
       
         
        mem_src=self.state.memory.load(src_addr,1)
        if self.state.solver.symbolic(mem_src) ==False:
            value=self.state.mem[src_addr.to_claripy()].string.concrete.decode('ascii')
            self.state.globals['extra_const_con'].append(value)
        else:
             self.state.globals['extra_const_symb'].append(src_len )
        
        self.inline_call(memcpy, dst_addr, src_addr,src_len+1)

        return dst_addr
