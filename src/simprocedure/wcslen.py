#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Dec 14 18:08:03 2020

@author: ali
"""

import angr

class wcslen(angr.SimProcedure): 
    def run(self, s): 
        print('in wcslen')
        f=angr.SIM_PROCEDURES['libc']['strlen'] 
        self.state.globals['iswchar']=True
        re = self.inline_call(f,s,wchar=True).ret_expr 
        return re
