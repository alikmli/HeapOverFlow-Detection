#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Nov 30 22:47:00 2020

@author: ali
"""

from analysis.MCSimulation import MCSimulation
from analysis.simprocedure.ExtractParams import SimExtractParams
from analysis.simprocedure.vul_strcpy import _strcpy_vul
from analysis.Tar3 import runTAR3,_correctInputs,_seperateValues
import angr,claripy,networkx as nx
from analysis.Units import Units 
from analysis.InitRun import InitRun
from analysis.TypeUtils import *


class VulAnalyzer(angr.Analysis):
    function_protos=['int sum(char *x,int *y,char* input)']
    def __init__(self):
        self._cfgAnlyzer = self.project.analyses.CFGPartAnalysis() 
        self._prototypes=self._setUpFunctionPrototypes()
        self._tree = self.project.analyses.VTree() 
        
        
        unit_spec=Units(self._cfgAnlyzer)
        wrpoint_res=unit_spec.getUnitForHeapBufferOverFlow()
        if wrpoint_res is not None:
            self._wrpoints=wrpoint_res

            
    
    def analyze(self,unit,args_index=[]):
        if ~self._cfgAnlyzer.isReachableFromMain(unit):
            raise ValueError('Can not reach the target unit ...')
        
        print('-'*32+"|Running Program with random inputs to Extract malloc's boundry")
        
        initRun=InitRun(self.project,'../mc.cfg',self._cfgAnlyzer)
        malloc_boundry=initRun.run(args_index)
        
        wr_points=self._getWritePointAt(unit) 
        print('wr_points',wr_points)
        self._tree.sefValsp(wr_points)
        self._tree.setMallocBoundry(malloc_boundry)
        pointer_idx,var=self._getBitVectorsAndPonterIdx(unit)
        unit_func=self._cfgAnlyzer.resolveAddrByFunction(self._cfgAnlyzer.getFuncAddress(unit))
        self._tree.generateForCallable(unit_func,*var)
        print(unit_func)
                
                
            
    def _getBitVectorsAndPonterIdx(self,unit):
        var=[]
        pointer_index=[]
        pointers=self._prototypes[unit]
        for numb,tp in pointers.items():
            var_name='var_{}'.format(numb)

            bit=getSymbolicBV(var_name,tp)
            var.append(bit)
            pointer_index.append(numb-1)

        return (pointer_index,var)
        
    def _getWritePointAt(self,callee):
        result=[]
        for malloc_addr,func_name,wr_list in self._wrpoints:
            if func_name == callee:
                result.append((malloc_addr,wr_list))
                
        return result
        
            
    
    def _setUpFunctionPrototypes(self):
        pointers={}
        for tp in VulAnalyzer.function_protos:
            name=tp[tp.index(' '):tp.index('(')]
            tp=tp.replace(name,' ')
            name=name.strip()
            tmp_res=angr.types.parse_type(tp)
            pointers[name]={}
            numb=1
            for arg in  tmp_res.args:
                arg_name=arg.name
                if '*' in arg_name:
                    arg_name=arg_name.replace('*','Pointer')
                pointers.get(name)[numb]=arg_name
                numb=numb+1
        return pointers
