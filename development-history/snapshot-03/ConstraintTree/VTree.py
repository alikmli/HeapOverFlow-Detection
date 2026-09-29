#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Sep 12 10:41:15 2020

@author: ali
"""

import angr,pyvex,claripy
import networkx as nx
from .VNode import _VNode
from analysis.simprocedure.vul_strcpy import _strcpy_vul




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
        #hooking
        addrs=list(self._func_wr_sites.keys()).copy() 
        self.project.hook_symbol('strcpy',_strcpy_vul(call_sites=addrs.copy()))
        
        
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
        
        current_vul_addr=addrs.pop(0) if len(addrs) > 0 else None
        while len(simgr.active) > 0 :
            act_state=simgr.active[0]
            vul_const=None
            if (current_vul_addr is not None) and (current_vul_addr in act_state.globals.keys()):
                rhs=act_state.globals.pop(current_vul_addr);
                vul_const=self.setUpVulConstraints(current_vul_addr,rhs)
                current_vul_addr=addrs.pop(0) if len(addrs) > 0 else None
                
                
            self._collect(act_state,True,extra_const=vul_const)
            simgr.step()
            if len(simgr.unsat)>0:
                unsat_state=simgr.unsat.pop()
                self._collect(unsat_state,False)
        
        # if 'spinning' in simgr.stashes:
        #         raise ValueError('unbounded loop , not supported yet!.')
                
                
        #un_hooking
        self.project.hook_symbol('strcpy',angr.SIM_PROCEDURES['libc']['strcpy']())
            
        return self._graph
    
    def setUpVulConstraints(self,addr,rhs):
        if addr not in self._func_wr_sites.keys():
            return None
        func_prp=self._func_wr_sites[addr]
        len_prp=len(func_prp)
        if len_prp == 3:
            func_name,arg1_prp,arg2_prp=func_prp
            if func_name == 'strcpy':
                dst_mac_addr=arg1_prp[0] if arg1_prp[1] == 'dst' else arg2_prp[0]
                src_mac_addr=arg1_prp[0] if arg1_prp[1] == 'src' else arg2_prp[0]
                len_dst=self._malloc_boundry[dst_mac_addr]
                len_src=self._malloc_boundry[src_mac_addr]
                if len_src > len_dst :
                    if isinstance(rhs,claripy.ast.bv.BV):
                        # return (rhs,len_dst)
                        # chops=rhs.chop(8)
                        # consts=[]
                        # for indx in range(len_dst + 1):
                        #     consts.append(chops[indx]!=0)
                        # return claripy.And(*consts)
                        return (rhs,len_dst)
                        
                
        elif len_prp ==2 :
            func_name,arg1_prp=func_prp
            if func_name == 'strcpy':
                if arg1_prp[1] =='dst':
                    len_dst=self._malloc_boundry[arg1_prp[0]]
                    if isinstance(rhs,str):
                        if len(rhs) > len_dst:
                            print('There is a buffer overflow in Function at address {} ....'.format(addr))
            
    
    def _collect(self,state,status,extra_const=None):
        #adding first Node and it's childs
        if len(self._graph.nodes) == 0:
            self._root=_VNode(inode=self._inode,block=state.addr,constraints=state.solver.constraints,satisfiable=status)
            self._inode= self._inode +1
            self._graph.add_node( self._root)
            self._checkForCalle(vex=state.block().vex,target=self._root)
            self._root._has_child=True
        else:

                                
            if self._isInCallableBoundry(self._func,state.addr) == False:
                return
            

            parent=self._findParent(state)
            node=_VNode(inode=self._inode,block=state.addr,satisfiable=status)
            node.addConstraints(state.solver.constraints,parent)
            if len(node.Term) == 0:
                parent.addBlock(state.addr)
                if extra_const is not None :
                    parent.addVulConstraint(extra_const)
                if state.block().vex.jumpkind == 'Ijk_Ret' or status == False:
                    parent._has_child=False
                else:
                    parent._has_child=True
                del(node)
                return
            else :
                if extra_const is not None :
                    node.addVulConstraint(extra_const)
                self._checkForCalle(vex=state.block().vex,target=node)
                self._inode= self._inode +1
                self._graph.add_edge( parent,node)
                
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