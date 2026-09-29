#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Sep 12 10:41:15 2020

@author: ali
"""

import angr,pyvex
import networkx as nx
from .VNode import _VNode




class _VTree(angr.Analysis):
    def __init__(self):
        self._graph=nx.DiGraph()
        self._root=None
        self._func=None
        self._inode=0
        self._allvars=[]
        self._vulsp=[]
        self._mapaddr_to_temp={}
        self._func_wr_sites={}
        self._wr_sites=[]
        self._malloc_boundry=None
    
    def sefValsp(self,address):
        for addr,wr_list in address:
            if isinstance(wr_list[0],tuple):
                for func,cb_addr,tp in wr_list:
                    if cb_addr not in self._func_wr_sites.keys():
                        self._func_wr_sites[cb_addr]=[func,(addr,tp)]
                    else:
                        self._func_wr_sites.get(cb_addr).append((addr,tp))
            else:
                self._wr_sites.append((addr,wr_list))

            
            
    def setMallocBoundry(self,boundry):
        self._malloc_boundry=boundry
    
    def _getVariableByName(self,name):
        for var in self._allvars:
            if name in var.variables:
                return var
            
        return None
    
    def generateForCallable(self,func,*args):
        
        #TODO set Loopseer for unbounded loop throwing excepting for this case
        self._func=func
        for arg in args:
            if isinstance(arg,angr.calling_conventions.PointerWrapper):
                self._allvars.append(arg.value)
            else:
                self._allvars.append(arg)
                
        state=self.project.factory.call_state(func.addr,*args,add_options={angr.options.TRACK_CONSTRAINTS})
        simgr=self.project.factory.simulation_manager(state,save_unsat=True)
        simgr.use_technique(angr.exploration_techniques.DFS())
                
        anloops=self.project.analyses.LoopFinder(functions=[self._func]) 
        if len(anloops.loops) > 0:
            raise ValueError('loop not suppoted!')
            # cfg = self.project.analyses.CFGFast(normalize=True)
            # simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, functions=func.name, bound=100, limit_concrete_loops=False))
            
        while len(simgr.active) > 0 :
            self._collect(simgr.active[0],True)
            simgr.step()
            if len(simgr.unsat)>0:
                unsat_state=simgr.unsat.pop()
                self._collect(unsat_state,False)
        
        # if 'spinning' in simgr.stashes:
        #         raise ValueError('unbounded loop , not supported yet!.')
            
        return self._graph
    
    
    def _collect(self,state,status):
        #adding first Node and it's childs
        if len(self._graph.nodes) == 0:
            self._root=_VNode(inode=self._inode,block=state.addr,constraints=state.solver.constraints,satisfiable=status)
            self._inode= self._inode +1
            self._graph.add_node( self._root)
            self._checkForCalle(vex=state.block().vex,target=self._root)
            self._root._has_child=True
        else:
            extra_conts={}
            if len(self._mapaddr_to_temp) != 0:
                delkeys=[]
                for addr,temp in self._mapaddr_to_temp.items():
                    if isinstance(temp,pyvex.IRExpr.RdTmp):
                        extra_conts[addr]=state.scratch.tmp_expr(temp.tmp)
                        delkeys.append(addr)
                    elif isinstance(temp,pyvex.expr.Const):
                        extra_conts[addr]=temp.con.value
                        delkeys.append(addr)
                        
                for addr in delkeys:
                    self._mapaddr_to_temp.pop(addr)
                del(delkeys)
                
                
            if self._isInCallableBoundry(self._func,state.addr) == False:
                parent=self._findParent(state)
                if len(extra_conts) > 0:
                    parent._extra_vul_const_rhs.append(extra_conts)
                return
            
            
            deladdr=[]    
            for ad in self._vulsp:
                if len(state.block().instruction_addrs) >0 and  ad in state.block().instruction_addrs:
                    self._mapaddr_to_temp[ad]=self.getStoreDataAtAddress(state.block().vex,ad)
                    deladdr.append(ad)
                    
            for ad in deladdr:
                self._vulsp.remove(ad)
            del(deladdr)

            parent=self._findParent(state)
            node=_VNode(inode=self._inode,block=state.addr,satisfiable=status)
            node.addConstraints(state.solver.constraints,parent)
            if len(node.Term) == 0:
                parent.addBlock(state.addr)
                if len(extra_conts) > 0:
                    parent._extra_vul_const_rhs.append(extra_conts)
                if state.block().vex.jumpkind == 'Ijk_Ret' or status == False:
                    parent._has_child=False
                else:
                    parent._has_child=True
                del(node)
                return
            else :
                self._checkForCalle(vex=state.block().vex,target=node)
                self._inode= self._inode +1
                self._graph.add_edge( parent,node)
                if len(extra_conts) > 0:
                    node._extra_vul_const_rhs.append(extra_conts)
                
            if state.block().vex.jumpkind == 'Ijk_Ret' or status == False:
                node._has_child=False
            else:
                node._has_child=True
            


   
    def _checkForCalle(self,vex,target):
        if 'Ijk_Call' in vex.constant_jump_targets_and_jumpkinds.values():
            addr=list(vex.constant_jump_targets)[0]
            target._addCallee(addr)   
            
            
    def getStoreDataAtAddress(self,vex,addr):
        visited=False
        target_store=None
        for stmt in vex.statements:
            if stmt.tag == 'Ist_IMark':
                if stmt.addr == addr:
                    visited=True
                else:
                    visited=False
           
            if visited==True :
                if isinstance(stmt,pyvex.IRStmt.Store):
                    target_store=stmt
        
        return target_store.data   
    
    def _isInCallableBoundry(self,func,target_addr):
        for i in func.blocks:
            if target_addr in i.instruction_addrs:
                return True
            
        return False
    
    def getNodeByIndex(self,index):
        return list(self._graph.nodes)[index]
    
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
