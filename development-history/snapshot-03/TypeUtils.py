#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jan  5 17:05:32 2021

@author: ali
"""


import claripy,angr

def integerEncoding(value):
    if value > 0:
        val=str(value)
        lenght=10-len(val)
        return bytes('0'*lenght + val,encoding='utf-8')
    else:
        return bytes(str(2**32 + value),encoding='utf-8')


def getIntConcreteBV(value):
    return claripy.BVV(integerEncoding(value))

def getCharStringConcreteBV(value):
    return claripy.BVV(value)

def getSymbolicBV(var_name,tp,exp_name=True):
    if 'charPointer' in tp:
        size=int(input("the {}'nth argument of your unit is char* Enter it's size: ".format(var_name.split('_')[1])))
        bit=claripy.BVS(var_name,size*8,explicit_name=exp_name)
    elif 'int' in tp:
        bit=claripy.BVS(var_name,32,explicit_name=exp_name)
    elif 'float' in tp:
        bit=claripy.FPS(var_name,claripy.FSORT_FLOAT,explicit_name=exp_name) 
    elif 'double' in tp:
        bit=claripy.FPS(var_name,claripy.FSORT_DOUBLE,explicit_name=exp_name) 
    elif  'char' in tp:
        bit=claripy.BVS(var_name,8,explicit_name=exp_name)
   
    if 'Pointer' in tp:
        return angr.PointerWrapper(bit)
    
    return bit
        
        
        
        
        
        
        
        
        
        
        
        