#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Feb 13 22:07:00 2021

@author: ali
"""


import angr,claripy

class _memcpy_vul(angr.SimProcedure): 
    def run(self,dst_addr, src_addr ,limit): 
        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        memcpy = angr.SIM_PROCEDURES['libc']['memcpy']
        
        src_len = self.inline_call(strlen, src_addr).ret_expr
        if self.state.solver.symbolic(limit) ==False:
            limit=self.state.solver.eval(limit.to_claripy())
        else:
            limit=limit.to_claripy()

        con_res=['memcpy',limit]
       
         
        mem_src=self.state.memory.load(src_addr,1)
        if self.state.solver.symbolic(mem_src) ==False:
            value=self.state.mem[src_addr.to_claripy()].string.concrete.decode('ascii')
            con_res.insert(1,value)
        else:
             con_res.insert(1,src_len)
            
            
        self.state.globals['extra_const'].append(tuple(con_res))
        
        self.inline_call(memcpy, dst_addr, src_addr,limit)

        return dst_addr
