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
from analysis.simprocedure.vul_strcat import _strcat_vul
from analysis.simprocedure.vul_memcpy import _memcpy_vul
from analysis.simprocedure.vul_memmove import _memmove_vul
from analysis.simprocedure.vul_memset import _memset_vul
from analysis.simprocedure.vul_sprintf import _sprintf_vul
import logging
from analysis.TypeUtils import *


class _VTree(angr.Analysis):
    def __init__(self,cfg_analyzer=None):
        logging.disable(logging.CRITICAL)
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
        self._malloc_args=None
        self.cfg_Analyzer=cfg_analyzer
        self._init_hook()
        self._vulReports=[]
        self._vulConstNumb=0
        self._generetedVulConst={}
    

    def _init_hook(self):
        self.project.hook_symbol('strcpy',_strcpy_vul())
        self.project.hook_symbol('strcat',_strcat_vul()) 
        self.project.hook_symbol('memcpy',_memcpy_vul())
        self.project.hook_symbol('memmove',_memmove_vul())
        self.project.hook_symbol('memset',_memset_vul())
        self.project.hook_symbol('sprintf',_sprintf_vul())
        
        
        
    def _rehooking(self):
        self.project.hook_symbol('strcpy',angr.SIM_PROCEDURES['libc']['strcpy']())
        self.project.hook_symbol('strcat',angr.SIM_PROCEDURES['libc']['strcat']())
        self.project.hook_symbol('memcpy',angr.SIM_PROCEDURES['libc']['memcpy']())
        self.project.hook_symbol('memmove',angr.SIM_PROCEDURES['libc']['memcpy']())
        self.project.hook_symbol('sprintf',angr.SIM_PROCEDURES['libc']['sprintf']())
        
        
    
    def sefValsp(self,address):
        for addr,wr_list in address:
            if isinstance(wr_list,tuple):
                func,cb_addr,tp = wr_list
                if cb_addr not in self._func_wr_sites.keys():
                    self._func_wr_sites[cb_addr]=[func,(addr,tp)]
                else:
                    tmp_res=(addr,tp)
                    if tmp_res not in self._func_wr_sites.get(cb_addr):
                        self._func_wr_sites.get(cb_addr).append((addr,tp))
            else:
                self._wr_sites.append((addr,wr_list))

    def setMallocArgs(self,malloc_args):
        self._malloc_args=malloc_args
            
    def setMallocBoundry(self,boundry):
        self._malloc_boundry=boundry
    
    def _getVariableByName(self,name):
        for var in self._allvars:
            if name in var.variables:
                return var
            
        return None
    
    def getVarNames(self):
        var_names=[]
        for var in self._allvars:
            name=list(var.variables)[0]
            var_names.append(name)
        return var_names
    
    def generateForCallable(self,func,*args):
        reportBlue('-'*4+"|Extracting Constraint Tree |-")
        self._func=func        
        for arg in args:
            if isinstance(arg,angr.calling_conventions.PointerWrapper):
                self._allvars.append(arg.value)
            else:
                self._allvars.append(arg)
                
        state=self.project.factory.call_state(func.addr,*args,add_options={angr.options.TRACK_CONSTRAINTS})
        state.libc.buf_symbolic_bytes=500
        state.libc.max_str_len=16*10
        state.globals['extra_const']=[]
        simgr=self.project.factory.simulation_manager(state,save_unsat=True)
        simgr.use_technique(angr.exploration_techniques.DFS())
                
        anloops=self.project.analyses.LoopFinder(functions=[self._func]) 
        if len(anloops.loops) > 0:
            raise ValueError('loop not suppoted!')
            # cfg = self.project.analyses.CFGFast(normalize=True)
            # simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, functions=func.name, bound=100, limit_concrete_loops=False))
        

        while len(simgr.active) > 0 :
            act_state=simgr.active[0]
            vul_const=None

            if len(act_state.globals['extra_const'])>0:
                rhs=act_state.globals['extra_const'].pop();
                target_call_hist=self._correctHistory( act_state.globals['block_addr'] )
                
                target_block_addr = target_call_hist[-1]
                target_vul_state=self.cfg_Analyzer.getBlockRelatedToAddr(target_block_addr)
                curr_wfCall=target_vul_state.instruction_addrs[-1]
                vul_const=self.setUpVulConstraints(target_vul_state.vex,curr_wfCall,rhs)
                

            
            
            self._collect(act_state,True,extra_const=vul_const)
            simgr.step()
            if len(simgr.unsat)>0:
                unsat_state=simgr.unsat.pop()
                self._collect(unsat_state,False,extra_const=vul_const)
        
        # if 'spinning' in simgr.stashes:
        #         raise ValueError('unbounded loop , not supported yet!.')
                
                
        #re_hooking
        self._rehooking()
        
        reportBlue('-'*4+"|Constraint Tree is generated and it consist of {} nodes|-",len(self._graph.nodes))
        

            
        return self._graph
    
    
    # def _setupVulConstraint(self,vul_cont,hist_addrs):
    #     parent=self._root
    #     hist_addrs.pop(0)
    #     while len(hist_addrs)>0:
    #         childs=self._successors(parent,depth_limit=1)
    #         active=hist_addrs.pop(0)
    #         for child in childs:
    #             if active in child.blocks:
    #                 parent=child
    #                 break
                
    #     childs=self._successors(parent,depth_limit=1)
    #     for child in childs:
    #         child.addVulConstraint(vul_cont)
    #         child.setVulSusp(True)

    
    def _isWrFuncCall(self,blk):
        for addr , props in self._func_wr_sites.items():
            if addr in blk.instruction_addrs:
                return addr
            
        return None
            
    
    def _getVarCorrToMallocAddrs(self,m_addr):
        for indx,addr in self._malloc_args.items():
            if addr == m_addr:
                return self._getVariableByName('var_{}'.format(indx))
                
        
    
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
                    vulConst,message=extra_const
                    parent.setVulSusp(True)
                    parent.addVulConstraint(vulConst)
                    parent.addVulMessage(message)
                    self._vulConstNumb=self._vulConstNumb+1
                    if parent.inode not in self._generetedVulConst.keys():
                        self._generetedVulConst[parent.inode]=[]
                    self._generetedVulConst.get(parent.inode).append(vulConst)
                if state.block().vex.jumpkind == 'Ijk_Ret' or status == False:
                    parent._has_child=False
                else:
                    parent._has_child=True
                parent.setSatisfaiablilyStatus(status)
                del(node)
                return
            else :
                if extra_const is not None :
                    vulConst,message=extra_const
                    node.addVulConstraint(vulConst)
                    node.setVulSusp(True)
                    node.addVulMessage(message)
                    self._vulConstNumb=self._vulConstNumb+1
                    if node.inode not in self._generetedVulConst.keys():
                        self._generetedVulConst[node.inode]=[]
                    self._generetedVulConst.get(node.inode).append(vulConst)
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
                
        return  hist
                
    def _findParent(self,state):
        hist=self._correctHistory(state.history.bbl_addrs.hardcopy)
        parent=self._root
        hist.pop(0)
        while len(hist)>0:
            childs=self._successors(parent,depth_limit=1)
            active=hist.pop(0)
            for child in childs:
                if active in child.blocks:
                    parent=child
                    break
        return parent
    
    def getAllPaths(self):
        """
            get All path of an DiGraph
        """
        roots = (v for v, d in self._graph.in_degree() if d == 0)
        leaves = [v for v, d in self._graph.out_degree() if d == 0]
        all_paths = []
        for root in roots:
            paths = nx.all_simple_paths(self._graph, root, leaves)
            all_paths.extend(paths)
            
        return all_paths
            
    def getVulSupsPaths(self):
        paths=[]
        for path in self.getAllPaths():
            for node in path :
                if node._vul_susp:
                    paths.append(path)
                    break
        return paths
    
    def isInVulSupsPath(self,inode):
        for path in self.getVulSupsPaths():
            for  node  in path :
                if node.inode == inode:
                    return True
        return False

        
    
    def _path_str_(self,path):
        l=[]
        for node in path: 
            l.append(str(node.inode))
        print('  \u2192 '.join(l))
        del(l)
    
    def _successors(self,parent,depth_limit):
        return list(nx.bfs_successors(self._graph,parent,depth_limit=depth_limit))[0][1]
    
    def _parent(self,target_node):
        return nx.predecessor(self._graph,source=self._root,target=target_node)[0]
    
    
    def setUpVulConstraints(self,curr_wfCall_vb,curr_wfCall,rhs):
        if curr_wfCall in self._func_wr_sites.keys():
            props=self._func_wr_sites[curr_wfCall]
            if props[0] == 'strcpy':
                return self._getVulConstraintsForStrcpy(curr_wfCall_vb,props,rhs)
            if props[0] == 'strcat':
                return self._getVulConstraintsForStrcat(curr_wfCall_vb,props,rhs)
            if props[0] == 'memcpy' or props[0] == 'memmove':
                return self._getVulConstraintsForMemcpy(curr_wfCall_vb,props,rhs)
            if props[0] == 'memset':
                return self._getVulConstraintsForMemset(curr_wfCall_vb,props,rhs)
            if props[0] == 'sprintf':
                return self._getVulConstraintsForSprintf(curr_wfCall_vb,props,rhs)
        
        
    def _getVulConstraintsForSprintf(self,vex,props,rhs):
        func_name,out_str=rhs
        if isinstance(out_str,str):
            dst_size=self._malloc_boundry[props[1][0]]
            dst_indexing=self.cfg_Analyzer._trackInputOfFuncionCall(vex,0,self.cfg_Analyzer.getFuncAddress('sprintf'),just_index=True)
            if dst_indexing is not None:
                dst_size=dst_size - dst_indexing[1].con.value
            
            if len(out_str) > dst_size:
                self._vulReports.append('There is a Buffer Overflow in block {} with target function sprintf '.format(vex.addr))
            

    def _getVulConstraintsForMemset(self,vex,props,rhs):
        func_name,num=rhs
        dst_size=self._malloc_boundry[props[1][0]]
        dst_indexing=self.cfg_Analyzer._trackInputOfFuncionCall(vex,0,self.cfg_Analyzer.getFuncAddress('memset'),just_index=True)
        message='There is a Buffer Overflow in block {} with target function memset '.format(vex.addr)
        if dst_indexing is not None:
            dst_size=dst_size - dst_indexing[1].con.value
        if isinstance(num,int):
            if num > dst_size:
                self._vulReports.append(message)
        else:
            return (num > dst_size,message)
                
            
            
        
    def _getVulConstraintsForMemcpy(self,vex,props,rhs):       
        func_name,src,limit=rhs
        message='There is a Buffer Overflow in block {0} with target function {1}'.format(vex.addr,props[0])
        if isinstance(limit,int):
            if isinstance(src,str):
                src_len=len(src)
                dst_size=self._malloc_boundry[props[1][0]]
                dst_indexing=self.cfg_Analyzer._trackInputOfFuncionCall(vex,0,self.cfg_Analyzer.getFuncAddress(props[0]),just_index=True)
                if dst_indexing is not None:
                    dst_size=dst_size - dst_indexing[1].con.value
                if src_len> limit and src_len > dst_size:
                    self._vulReports.append(message)
                
            else:
                src_size,dst_size=self._getSRCandDSTsize('memcpy',vex,props)
                const=[src>limit,limit<=src_size,src>dst_size]
                return (claripy.And(*const),message)
        else:
                src_size,dst_size=self._getSRCandDSTsize('memcpy',vex,props)
                const=[src>limit,limit<=src_size,src>dst_size]
                return (claripy.And(*const),message)
                
            
    def _getVulConstraintsForStrcpy(self,vex,props,rhs):
        message='There is a Buffer Overflow in block {} with target function strcpy'.format(vex.addr)
        if isinstance(rhs,str):
            dst_size=self._malloc_boundry[props[1][0]]
            dst_indexing=self.cfg_Analyzer._trackInputOfFuncionCall(vex,0,self.cfg_Analyzer.getFuncAddress('strcpy'),just_index=True)
            if dst_indexing is not None:
                dst_size=dst_size - dst_indexing[1].con.value
            len_rhs=len(rhs)
            if len_rhs >  dst_size:
                self._vulReports.append(message)
        elif len(props) == 3:

            src_size,dst_size=self._getSRCandDSTsize('strcpy',vex,props)
            const=[]
            if src_size < dst_size:
                return None
            
            const.append(claripy.UGT(rhs ,dst_size+1))
            const.append(claripy.ULT(rhs,src_size))
            return (claripy.And(*const),message)
    
    def _getSRCandDSTsize(self,func_name,vex,props):
        dst_addr=None
        src_addr=None
        for addr,tp in props[1:]:
            if tp == 'dst':
                dst_addr=addr
            elif tp == 'src':
                src_addr=addr
        
        src_size=self._malloc_boundry[src_addr]
        dst_size=self._malloc_boundry[dst_addr]
        dst_indexing=self.cfg_Analyzer._trackInputOfFuncionCall(vex,0,self.cfg_Analyzer.getFuncAddress(func_name),just_index=True)
        src_indexing=self.cfg_Analyzer._trackInputOfFuncionCall(vex,1,self.cfg_Analyzer.getFuncAddress(func_name),just_index=True)
        if dst_indexing is not None:
            dst_size=dst_size - dst_indexing[1].con.value
        if src_indexing is not None:
            src_size=src_size - src_indexing[1].con.value
        return (src_size,dst_size)
        
    def _getVulConstraintsForStrcat(self,vex,props,rhs):
        func_name,dst_len,src_len=rhs
        message='There is a Buffer Overflow in block {} with target function strcat'.format(vex.addr)
        if isinstance(src_len,int):
            dst_size=self._malloc_boundry[props[1][0]]
            return (dst_size - dst_len <  src_len,message)
        else:
            src_size,dst_size=self._getSRCandDSTsize('strcat',vex,props)
            const=[dst_size - dst_len < src_len , src_len < src_size]
            return (claripy.And(*const),message)
                    
        
        
        
        
        
        
        
        
        