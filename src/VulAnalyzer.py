#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Nov 30 22:47:00 2020

@author: ali
"""

from .MCSimulation import MCSimulation
from .simprocedure.ExtractParams import SimExtractParams
from .simprocedure.vul_strcpy import _strcpy_vul
from .learning.Tar3 import runTAR3,_correctInputs,_seperateValues
import angr,claripy,networkx as nx
from .analysis import Units 
from .learning import Cover
from .TypeUtils import *
import time


class VulAnalyzer(angr.Analysis):
    def __init__(self,cfg_an):
        self._tstart = time.time()
        self._cfgAnlyzer = cfg_an
        self._tree = self.project.analyses.VTree(self._cfgAnlyzer ) 

        
        
        self._unit_spec=Units(self._cfgAnlyzer)
        wrpoint_res=self._unit_spec.getUnitForHeapBufferOverFlow()
        self._malloc_args=self._unit_spec._getMallocPosOnArgs()
        if wrpoint_res is not None:
            self._wrpoints=wrpoint_res
            

            
    def propUnits(self):
        units=set()
        for addr,func,props in self._wrpoints:
            units.add(func)
        
        print('-'*80)
        reportVul("\Oops, your not specify the unit name and it's prototype u can set it with -n and -s options")
        reportBold('-|critical units are : ')
        for unit in units:
            reportBlue('-'*22+"|{}",unit)
            reportBlue('-'*25+"|{}","You Can reach it Throw This Chains :")
            for chain in self._cfgAnlyzer.getCallChain(unit):
                value=chain.replace('-' , '  \u2192 ')
                reportBlue('-'*30+"|{}",value)
        
        
        
    def analyze(self,unit,unit_protoType,args_index=[],arg_sizes=[]):
        self._prototypes=self._setUpFunctionPrototypes(unit_protoType)
        if self._cfgAnlyzer.isReachableFromMain(unit) == False:
            raise ValueError('Can not reach the target unit ...')
        
        print('-'*80)
        reportBold('\nSteps')
        
        malloc_boundry=self.getMallocsBoundries()
        argStatus=self._prototypes[unit]
        wr_points=self._getWritePointAt(unit) 
        reportBlack('-'*4+'| 1.{}','Extracting Constraint Tree ')
        self._tree.sefValsp(wr_points)
        self._tree.setMallocBoundry(malloc_boundry)
        mc=MCSimulation('NFACTOR_MC.cfg',nfactor=True)
        if len(args_index) > 0:
            argv={}
            for idx in args_index:
                size=mc.getVarTypes(idx-1)
                argv[idx]=int(size[1])
            self._tree.setupArgv(argv)
        
        if self._malloc_args and unit in self._malloc_args.keys():
            self._tree.setMallocArgs(self._malloc_args[unit])
        
        malloc_relativeAddr=self._unit_spec.searchInMaps(unit)
        self._tree.setUpMallocRelativeAddr(malloc_relativeAddr)
        pointer_idx,var=self._getBitVectorsAndPonterIdx(unit,malloc_boundry,arg_sizes)
        unit_func=self._cfgAnlyzer.resolveAddrByFunction(self._cfgAnlyzer.getFuncAddress(unit))
        st=time.time()
        self._tree.generateForCallable(unit_func,*var)
        ed=time.time()

        mallocArgsSz=self._getMallocSzForUnit(malloc_boundry,unit)
        

        
        reportBlack('-'*4+'| 2.{}','Applying Cover Algorithm ')
        coverstartTime=time.time()
        self.cover=Cover(mc,self.project,self._cfgAnlyzer,self._tree,unit_func,unitArgsStatus=argStatus,mallocArgSz=mallocArgsSz)
        result=self.cover.cover(1,pointer_indexes=pointer_idx,args_index=args_index)
        coverendTime=time.time()
        
        
        
        
        self._tend = time.time()
        if result == -1:
            reportBold("\nCover Algorithm did not Appplied")
        else :
            reportBold('\nCover Algorithm Takes {} seconds to finish'.format(coverendTime-coverstartTime))
        reportBold('\nAnalysis takes {} seconds to finish'.format(self._tend - self._tstart))
        
        
        if len(self._tree._generetedVulConst)>0:
            reportBlack('\ngenerated Vulnerability constraints are : ')
            for inode,vul_const in self._tree._generetedVulConst.items():
                reportBlue('-| for node ' + str(inode) , ' ...  ' )
                reportVul('-'*20+'| {}',vul_const)
                
        reportBlack('\nTotal generated Vulnerability Cnstraint is : {}\n',self._tree._vulConstNumb )    
        
        if len(self._tree._vulReports)==0 and (result and (result == -1 or len(result) == 0)):
            reportBold("Analysis doesn't found any vulnerability")
            return result
        

        if len(self._tree._vulReports) > 0:
            reportBold('\n--|Dicovered Vulnerabilities in functions with concrete arguments')
            for report in set(self._tree._vulReports):
                reportVul("---|{}",report)
            if result == -1 :
                return 
        
        
        if result and ( len(result) >0 or len(self.cover._unsats)>0):
            reportBold('Nodes Status :')
            
            nodes=list(self._tree._graph.nodes)
            if len(result) > 0 :
                for inode,inputs in result.items():
                    node=self._tree.getNodeByInode(inode)
                    if len(inputs) > 0:
                        reportBold('\n-|For Node With Inode {} : \n ',inode)
                        
                        reportBold('Number of Constraints For This Node {} ',len(node.constraints))
                        reportBold('Number of Vulnerability Constraints are {}\n',len(node._extra_vul_const))
                        
                        for msg in nodes[inode]._vulMsg:
                            reportVul('--|{}',msg)
                        reportBlack('\n\-|You Can reach it with these inputs : ')
                        for inp in inputs:
                            reportVul('--|{}',inp)
                            
            if len(self.cover._unsats) > 0:
                reportBold('-|Unsat Nodes are :')
                for msg,node_index in self.cover._unsats:
                    node=self._tree.getNodeByInode(node_index)
                    reportBlue('--|{}',msg)
                    reportBlue('----|Number of Constraints For This Node {} ',len(node.constraints))
                
        return result
                
       
                
    def getMallocsBoundries(self):
        result={}
        for addr , func in self._cfgAnlyzer.getAddressOfFunctionCall('malloc'):
            b=self._cfgAnlyzer.getBlockRelatedToAddr(addr) 
            sz=self._cfgAnlyzer.getMallocSize(b.vex,func.name)
            if sz:
                result[addr]=sz
                
        return result
    
    def _getBitVectorsAndPonterIdx(self,unit,malloc_boundry,arg_sizes):
        var=[]
        pointer_index=[]
        pointers=self._prototypes[unit]
        for numb,tp in pointers.items():
            var_name='var_{}'.format(numb)
            sz=None
            if tp == 'charPointer' or tp=='struct':
                sz=arg_sizes[numb-1]
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
        
            
    
    def _setUpFunctionPrototypes(self,protoType):
        pointers={}
        name=protoType[protoType.index(' '):protoType.index('(')]
        protoType=protoType.replace(name,' ')
        name=name.strip()
        tmp_res=angr.types.parse_type(protoType)
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
        if self._malloc_args and  unit in self._malloc_args:
            unitArgMallocSize=self._malloc_args[unit]
            res={}
            for arg_numb,m_addr in unitArgMallocSize.items():
                res[arg_numb]=malloc_boundry.get(m_addr)
            return res









 
