#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Sep 12 10:41:15 2020

@author: ali
"""

import angr
import networkx as nx
from .VNode import _VNode




class _VTree(angr.Analysis):
    def __init__(self):
        self._graph=nx.DiGraph()
        self._root=None
        self._func=None
        self._inode=0
    
    def generateForCallable(self,func,*args):
        self._func=func
        state=self.project.factory.call_state(func.addr,*args,add_options={angr.options.TRACK_CONSTRAINTS})
        simgr=self.project.factory.simulation_manager(state,save_unsat=True)
        simgr.use_technique(angr.exploration_techniques.DFS())
        while len(simgr.active) > 0 :
            self._collect(simgr.active[0],True)
            simgr.step()
            if len(simgr.unsat)>0:
                unsat_state=simgr.unsat.pop()
                self._collect(unsat_state,False)
            
        return self._graph
    
    
    def _collect(self,state,status):
        #adding first Node and it's childs
        if len(self._graph.nodes) == 0:
            self._root=_VNode(inode=self._inode,block=state.addr,constraints=state.solver.constraints,satisfiable=status)
            self._inode= self._inode +1
            self._graph.add_node( self._root)
            self._checkForCalle(vex=state.block().vex,target=self._root)
        else:
            if self._isInCallableBoundry(self._func,state.addr) == False:
                return
            
            
            parent=self._findParent(state)
            
            node=_VNode(inode=self._inode,block=state.addr,satisfiable=status)
            node.addConstraints(state.solver.constraints,parent)
            self._checkForCalle(vex=state.block().vex,target=node)
            self._inode= self._inode +1
            self._graph.add_edge( parent,node)
            
            if state.block().vex.jumpkind == 'Ijk_Ret':
                parent._has_child=False
            else:
                parent._has_child=True
            


   
    def _checkForCalle(self,vex,target):
        if 'Ijk_Call' in vex.constant_jump_targets_and_jumpkinds.values():
            addr=list(vex.constant_jump_targets)[0]
            target._addCallee(addr)   
            
            
            
    def _isInCallableBoundry(self,func,target_addr):
        for i in func.blocks:
            if target_addr in i.instruction_addrs:
                return True
            
        return False
    
    
    
    def _correctHistory(self,bbl_addrs):
        hist=[]
        for addr in bbl_addrs:
            if self._isInCallableBoundry(self._func,addr):
                hist.append(addr)
                
        hist.reverse()
        return  hist
                
    def _findParent(self,state):
        hist=self._correctHistory(list(state.history.bbl_addrs).copy())
        parent=self._root
        hist.pop()
        while len(hist)>0:
            childs=self._successors(parent,depth_limit=1)
            active=hist.pop()
            for child in childs:
                if active in child.blocks:
                    parent=child
                    break
        return parent
            
    
    def _successors(self,parent,depth_limit):
        return list(nx.bfs_successors(self._graph,parent,depth_limit=depth_limit))[0][1]
    
    def _parent(self,target_node):
        return nx.predecessor(self._graph,source=self._root,target=target_node)[0]