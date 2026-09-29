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
from analysis.Cover import Cover
from analysis.TypeUtils import *
import logging
import time


class VulAnalyzer(angr.Analysis):
    function_protos=['int sum(char *x,int *y,char* input)']
    def __init__(self,cfg_an):
        self._tstart = time.time()
        logging.disable(logging.CRITICAL)
        self._cfgAnlyzer = cfg_an
        self._prototypes=self._setUpFunctionPrototypes()
        self._tree = self.project.analyses.VTree(self._cfgAnlyzer ) 
        logging.disable(logging.CRITICAL)
        
        
        unit_spec=Units(self._cfgAnlyzer)
        wrpoint_res=unit_spec.getUnitForHeapBufferOverFlow()
        self._malloc_args=unit_spec._getMallocPosOnArgs()
        if wrpoint_res is not None:
            self._wrpoints=wrpoint_res

            
    
    def analyze(self,unit,malloc_boundry,args_index=[]):
        if self._cfgAnlyzer.isReachableFromMain(unit) == False:
            raise ValueError('Can not reach the target unit ...')
        
        print('-'*80)
        print('-'*32+"|Running Program with random inputs to Extract malloc's boundry|-")
        
 
        argStatus=self._prototypes['stOpr']
        wr_points=self._getWritePointAt(unit) 
        self._tree.sefValsp(wr_points)
        self._tree.setMallocBoundry(malloc_boundry)
        self._tree.setMallocArgs(self._malloc_args[unit])
        pointer_idx,var=self._getBitVectorsAndPonterIdx(unit,malloc_boundry)
        unit_func=self._cfgAnlyzer.resolveAddrByFunction(self._cfgAnlyzer.getFuncAddress(unit))
        self._tree.generateForCallable(unit_func,*var)
        mallocArgsSz=self._getMallocSzForUnit(malloc_boundry,unit)
        cover=Cover('../mc.cfg',self.project,self._cfgAnlyzer,self._tree,unit_func,unitArgsStatus=argStatus,mallocArgSz=self._malloc_args[unit])
        result=cover.cover(1,pointer_indexes=pointer_idx,args_index=args_index)
        
        
        
        self._tend = time.time()
        reportBlack('Analysis takes {} seconds to finish'.format(self._tend - self._tstart))
        
        if len(self._tree._generetedVulConst)>0:
            reportBlack('generated Vulnerability constraints are : ')
            for inode,vul_const in self._tree._generetedVulCons.items()t:
                reportBlue('for node ' +inode , '   ,   ' ,vul_const)
                
        reportBlack('Total generated Vulnerability Cnstraint is : {}',self._tree._vulConstNumb )    
        
        if len(self._tree._vulReports)==0 and len(result) == 0:
            reportBold("Analysis doesn't found any vulnerability")
        
        if len(self._tree._vulReports) > 0:
            reportBold('----|Dicovered Vulnerabilities in functions with concrete arguments')
            for report in self._tree._vulReports:
                reportVul(report)
        
        nodes=list(self._tree._graph.nodes)
        if len(result) > 0 :
            for inode,inputs in result.items():
                reportBold('For Node With Inode {} : ',inode)
                for msg in nodes[inode]._vulMsg;
                    reportBlue(msg)
                reportBlue('You Can reach it with these inputs : ')
                for inp in inputs:
                    reportVul(inp)
                
       
                
    


    
    def _getBitVectorsAndPonterIdx(self,unit,malloc_boundry):
        var=[]
        pointer_index=[]
        pointers=self._prototypes[unit]
        for numb,tp in pointers.items():
            var_name='var_{}'.format(numb)
            sz=None
            if tp == 'charPointer':
                sz=malloc_boundry.get(self._malloc_args[unit].get(numb))
            bit=getSymbolicBV(var_name,tp,size=sz)
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
    
    def _getMallocSzForUnit(self,malloc_boundry,unit):
        unitArgMallocSize=self._malloc_args[unit]
        res={}
        for arg_numb,m_addr in unitArgMallocSize.items():
            res[arg_numb]=malloc_boundry.get(m_addr)
        return res









