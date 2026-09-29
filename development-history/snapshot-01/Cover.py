#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 22 11:42:35 2020

@author: ali
"""
from analysis.MCSimulation import MCSimulation
from analysis.SimExtractIntPointerParams import SimExtractIntPointerParams
from analysis.Tar3 import runTAR3

class Cover:
    
    def __init__(self,project,CFGAnalysis,TreeAnalysis,target_func,*args):
        self.project=project
        self.analysis = CFGAnalysis
        self.target_func = target_func
        self.tree=TreeAnalysis
        self.tree.generateForCallable(self.target_func, *args)
        
        
    def _extractUnitV(self,*args):
        sign=lambda x:  '+{}'.format(x) if (x>0) else '{}'.format(x)
        self.project.hook_symbol(self.target_func.name,SimExtractIntPointerParams())
        sys_V=[]
        for var in args:
            sys_V.append(claripy.BVV(bytes(sign(var),encoding='utf-8')))
        bytes_ast = claripy.Concat(*sys_V)
        simfile=angr.SimFileStream('/dev/stdin',content=bytes_ast)
        state=self.project.factory.entry_state(stdin=simfile)
        simgr=self.project.factory.simulation_manager(state)
        simgr.run()
        return simgr.deadended[0].globals
    
    def cover(self,config_filename,pointer_indexes=None):
        self._generatingVitness(config_filename,pointer_indexes)
        root=list(self.tree._graph.nodes)[0]
        for node in nx.bfs_tree(self.tree._graph,source=root):
            if node is not root:
                parent=self.tree._parent(node)
                siblings=self.tree._successors(parent=parent,depth_limit=1)
                if self._covered(siblings):
                    VV=node.v
                    VVV=[]
                    V=[]
                    for item in root.v:
                        V.append(item.copy())
                        if item not in VV:
                            VVV.append(item.copy())
                    runTAR3(root.V,V,VV,VVV,node.inode)
                    
                else:
                    pass
                
        
        
        
    def _covered(self,siblings):
        for node in siblings:
            if len(node.v) == 0:
                return False
        return True
    
    
    #V -> W
    
    def _generatingVitness(self,config_filename,pointer_indexes=None):
        mc=MCSimulation(config_filename)
        inputs=mc.generate()
        sys_V=[]
        for var in inputs:
            sys_V=list(map(int,var))
            unit_v=self._extractUnitV(*sys_V)
            self._callUnit(unit_v,pointer_indexes,sys_V)
            
    

    def _callUnit(self,unit_v,pointers_indexes,sys_V):
        var=[]
        for i in range(0,len(unit_v)):
            if i in pointers_indexes:
                var.append(self.project.factory.callable.PointerWrapper(unit_v[i]))
            else:
                var.append(unit_v[i])
                
        
        self.project.unhook_symbol(self.target_func.name)
        call_obj=self.project.factory.callable(self.target_func.addr,concrete_only=True) 
        call_obj.perform_call(*var)
        add=list(call_obj.result_state.history.bbl_addrs)

        root=None
        for i in add:
            if root is None:
                root=list(self.tree._graph.nodes)[0]
                if (i in root.blocks) or (i in root._called):
                    root.addUnitIn(unit_v)
                    root.addSystemIn(sys_V)
            else:
                children=self.tree._successors(root,depth_limit=1)
                for child in children:
                    if i in child.blocks:
                        child.addUnitIn(unit_v)
                        child.addSystemIn(sys_V)
                        root=child
                        break


                
            
            
            
        


        
