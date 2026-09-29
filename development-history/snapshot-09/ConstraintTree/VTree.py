p#!/usr/bin/env python3
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
from analysis.simprocedure.wcslen import wcslen
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
        self._func_wr_sites={}
        self._wr_sites=[]
        self._malloc_boundry=None
        self._malloc_args=None
        self.cfg_Analyzer=cfg_analyzer
        self._init_hook()
        self._vulReports=[]
        self._vulConstNumb=0
        self._generetedVulConst={}
        self._loopsAddrs=[]
        self._loopentries=[]
        self._loop_breadedges=[]
        self._loopsFirstNodes=[]
        self._loopTerm=None
        self._malloc_relativeAddr={}
        self._activeWRmalloc_bnd={}
    

    def _init_hook(self):
        self.project.hook_symbol('wcslen',wcslen())
        self.project.hook_symbol('strcpy',_strcpy_vul())
        self.project.hook_symbol('strcat',_strcat_vul()) 
        self.project.hook_symbol('memcpy',_memcpy_vul())
        self.project.hook_symbol('memmove',_memmove_vul())
        self.project.hook_symbol('memset',_memset_vul())
        self.project.hook_symbol('sprintf',_sprintf_vul())
        
        

    
    
    def _rehooking(self):
        self.project.hook_symbol('wcslen',angr.SIM_PROCEDURES['libc']['strlen']())
        self.project.hook_symbol('strcpy',angr.SIM_PROCEDURES['libc']['strcpy']())
        self.project.hook_symbol('strcat',angr.SIM_PROCEDURES['libc']['strcat']())
        self.project.hook_symbol('memcpy',angr.SIM_PROCEDURES['libc']['memcpy']())
        self.project.hook_symbol('memset',angr.SIM_PROCEDURES['libc']['memset']())
        self.project.hook_symbol('memmove',angr.SIM_PROCEDURES['libc']['memcpy']())
        self.project.hook_symbol('sprintf',angr.SIM_PROCEDURES['libc']['sprintf']())
        
    
    def setUpMallocRelativeAddr(self,address):
        for m_addr,records in address:
            self._malloc_relativeAddr[m_addr]=(claripy.BVV(records[1].con.value,64),records[2])
    
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
    
    def generateForCallable(self,func,*args,loop_bound=100):
        self._func=func        
        for arg in args:
            if isinstance(arg,angr.calling_conventions.PointerWrapper):
                self._allvars.append(arg.value)
            else:
                self._allvars.append(arg)
                
        self._state=self.project.factory.call_state(func.addr,*args,add_options={angr.options.TRACK_CONSTRAINTS})
        self._state.libc.buf_symbolic_bytes=500
        self._state.libc.max_str_len=16*10
        self._state.globals['extra_const']=[]
        self._simgr=self.project.factory.simulation_manager(self._state)
        self._simgr.use_technique(angr.exploration_techniques.DFS())
                
        self.anloops=self.project.analyses.LoopFinder(functions=[self._func]) 
        if len(self.anloops.loops) > 0:
            cfg = self.project.analyses.CFGFast(normalize=True)
            self._simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, functions=func.name,use_header=True, bound=loop_bound,bound_reached=self.bnd_reached))
            for loop in self.anloops.loops:
                self._setLoopsBound(loop)
                self._loopentries.append(loop.entry.addr)
                self._extractLoopFirstNode(loop)
                for en , ex in loop.break_edges:
                    self._loop_breadedges.append((en.addr,ex.addr))


        while len(self._simgr.active) > 0 :
            act_state=self._simgr.active[0]
            vul_const=None

            if len(act_state.globals['extra_const'])>0:
                rhs=act_state.globals['extra_const'].pop();
                target_call_hist=self._correctHistory( act_state.globals['block_addr'] )
                
                target_block_addr = target_call_hist[-1]
                target_vul_state=self.cfg_Analyzer.getBlockRelatedToAddr(target_block_addr)
                curr_wfCall=target_vul_state.instruction_addrs[-1]
                iswchar=False
                if 'iswchar' in act_state.globals.keys() and act_state.globals['iswchar']==True:
                    iswchar=True
                vul_const=self.setUpVulConstraints(target_vul_state.vex,curr_wfCall,rhs,iswchar)
                

            
            
            self._collect(act_state,True,extra_const=vul_const)
            self._simgr.step()
        
                
                
        #re_hooking
        self._rehooking()
        
        return self._graph
    

    
    def bnd_reached(self,seer,succ_state):
        state_addr=self._getExitNodeAddr(succ_state.addr)
        if state_addr:
            state=self.project.factory.blank_state(addr=state_addr,plugins=succ_state.plugins)
            self._simgr.deferred.append(state) 

    
    
    def _getExitNodeAddr(self,addr):
        for en_addr,ex_addr in self._loop_breadedges:
            if addr == en_addr:
                return ex_addr
            
            
    def _isWrFuncCall(self,blk):
        for addr , props in self._func_wr_sites.items():
            if addr in blk.instruction_addrs:
                return addr
            
        return None

    def _setLoopsBound(self,loop):
        addr=[]
        for loopNode in loop.body_nodes:
            addr.append(loopNode.addr)
            
        self._loopsAddrs.append(addr)
        
        
    def _getVarCorrToMallocAddrs(self,m_addr):
        for indx,addr in self._malloc_args.items():
            if addr == m_addr:
                return self._getVariableByName('var_{}'.format(indx))
                
        
    def getNodeByInode(self,inode):
        for node in self._graph.nodes:
            if node.inode == inode:
                return node 
            
            
            
    def _collect(self,state,status,extra_const=None):
        if len(self._graph.nodes) == 0:
            self._root=_VNode(inode=self._inode,addr=state.addr,block=state.addr,constraints=state.solver.constraints,parent_addr=0,satisfiable=status)
            self._inode= self._inode +1
            self._graph.add_node( self._root)
            self._checkForCalle(vex=state.block().vex,target=self._root)
            self._root._has_child=True
            
            wr_st_maps=self._getWrSiteINState(state)
            if len(wr_st_maps) > 0:
                self._checkWrSiteVul(state,wr_st_maps)
        else:

                                
            if self._isInCallableBoundry(self._func,state.addr) == False:
                return
            
            
            wr_st_maps=self._getWrSiteINState(state)
            if len(wr_st_maps) > 0:
                self._checkWrSiteVul(state,wr_st_maps)
            
            parent,parent_add,path=self._findParent(state)
                        
            node=_VNode(inode=self._inode,addr=state.addr,block=state.addr,parent_addr=parent_add,satisfiable=status)
            node.addConstraints(state.solver.constraints,parent)
            
            flag=False
            if len(self._loopsAddrs) > 0:
                if self._isINLoop(state.addr):
                    flag=True
                    isEntry=node.addr in self._loopentries
                    isFirstNode= node.addr in self._loopsFirstNodes
                    if isEntry:
                        self._loopTerm=None
                    if isFirstNode:
                        if len(node.Term)> 0:
                            self._loopTerm=node.Term
                    for p_node in path:
                        if p_node.isEqual(node,isEntryLoop=isEntry):
                            if self._loopTerm:
                                p_node.constraints.extend(self._loopTerm)
                                if isFirstNode:
                                    p_node.Term.extend(self._loopTerm)
                            parent.addBlock(state.addr)
                            return
                            

                
            

            if len(node.Term) == 0 and flag == False:
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
                self._graph.add_edge( parent,node)
                self._inode= self._inode +1
                
            if state.block().vex.jumpkind == 'Ijk_Ret' or status == False:
                node._has_child=False
            else:
                node._has_child=True
            

    def _getWrSiteINState(self,state):
        res={}
        if len(self._wr_sites)>0:
            inst_addrs=state.block().instruction_addrs
            for base_addr,list_wr_addrs  in self._wr_sites:
                for wr_addr in list_wr_addrs:
                    if wr_addr in inst_addrs:
                        if base_addr not in res.keys():
                            res[base_addr]=[wr_addr]
                        else:
                            res[base_addr].append(wr_addr)
            
        return res
    
    def _checkWrSiteVul(self,state,wr_sites):
        if self._isINLoop(state.addr):
            # print('wr_sites',wr_sites)
            for m_addr,wrAddr_list in wr_sites.items():
                if m_addr not in self._activeWRmalloc_bnd.keys():
                    malloc_re,op=self._malloc_relativeAddr[m_addr]
                    if 'Iop_Add' in op:
                        base=state.mem[state.regs.rbp+malloc_re].uint64_t.resolved
                    elif 'Iop_Sub' in op:
                        base=state.mem[state.regs.rbp-malloc_re].uint64_t.resolved
                    end=base + self._malloc_boundry[m_addr]
                    self._activeWRmalloc_bnd[m_addr]=(base,end)
             
            for m_addr,wrAddr_list in wr_sites.items():
                for wr_addr in wrAddr_list:
                    store=self.cfg_Analyzer.getStoreInTargetAddr(wr_addr,state.block().vex)
                    if isinstance(store.addr,pyvex.expr.RdTmp):
                        #get regs that this tmp is store into
                            try:
                                accessed_addr=state.scratch.tmp_expr(store.addr.tmp)
                                base,end=self._activeWRmalloc_bnd[m_addr]
                                if isinstance(accessed_addr,claripy.ast.bv.BV) and accessed_addr.size()==base.size()==end.size():
                                    if base.concrete and end.concrete and accessed_addr.concrete:
                                        if accessed_addr > base and accessed_addr > end :
                                            message='There is a Buffer Overflow in block {} with constant write '.format(wr_addr)
                                            if message not in self._vulReports:
                                                self._vulReports.append(message)
                            except angr.SimValueError:
                                pass
            
        else:
            for m_addr,wr_list in wr_sites.items():
                for wr_addr in wr_list:
                    store=self.cfg_Analyzer.getStoreInTargetAddr(wr_addr,state.block().vex)
                    if isinstance(store.data,pyvex.expr.Const):
                        if isinstance(store.addr,pyvex.expr.RdTmp):
                            target_wr=self.cfg_Analyzer.targetWrTempByTempName(state.block().vex,str(store.addr))
                            if target_wr and isinstance(target_wr.data,pyvex.expr.Binop):
                                arg1,arg2=target_wr.data.args
                                if isinstance(arg2,pyvex.expr.Const):
                                    index=arg2.con.value
                                    malloc_size=self._malloc_boundry[m_addr]
                                    if index >= malloc_size:
                                        message='There is a Buffer Overflow in block {} with constant write '.format(wr_addr)
                                        if message not in self._vulReports:
                                            self._vulReports.append(message)
                            elif target_wr and isinstance(target_wr.data,pyvex.expr.Load ):
                                write_value=store.data.con.value
                                malloc_size=self._malloc_boundry[m_addr] *8
                                max_value=2**malloc_size
                                if write_value >= max_value:
                                    message='There is a Buffer Overflow in block {} with constant write '.format(wr_addr)
                                    if message not in self._vulReports:
                                        self._vulReports.append(message)
                    else:
                        target_wr=self.cfg_Analyzer.targetWrTempByTempName(state.block().vex,str(store.data))
                        if  target_wr and isinstance(target_wr.data,pyvex.expr.Load ):
                            if isinstance(target_wr.data.addr,pyvex.expr.Const):
                                wrvalue_addr=target_wr.data.addr.con.value
                                malloc_size=self._malloc_boundry[m_addr] *8
                                if malloc_size == 32:
                                    wr_bv=state.mem[wrvalue_addr].float.resolved
                                    if wr_bv.concrete:
                                        wr_value=wr_bv.args[0]
                                        if str(wr_value) == 'inf':
                                            message='There is a Buffer Overflow in block {} with constant write '.format(wr_addr)
                                            if message not in self._vulReports:
                                                self._vulReports.append(message)
                                else:
                                    wr_bv=state.mem[wrvalue_addr].double.resolved
                                    if wr_bv.concrete:
                                        wr_value=wr_bv.args[0]
                                        if wr_value > malloc_size:
                                            message='There is a Buffer Overflow in block {} with constant write '.format(wr_addr)
                                            if message not in self._vulReports:
                                                self._vulReports.append(message)
                                
                    
                    
                    
                    
    
    ###
    def _extractLoopFirstNode(self,loop):
        for en,ex in loop.graph.edges:
            en_addr=en.addr
            ex_addr=ex.addr
            if en_addr in self._loopentries:
                if (en_addr,ex_addr) not  in self._loop_breadedges:
                    self._loopsFirstNodes.append(ex_addr)
                    return
            
    
    def _isINLoop(self,addr):
        for loopaddrs in self._loopsAddrs:
            if addr in loopaddrs:
                return True
            
        return False
    
    
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
        path=[parent]
        active=hist.pop(0)
        while len(hist)>0:
            childs=self._successors(parent,depth_limit=1)
            active=hist.pop(0)
            for child in childs:
                if active in child.blocks:
                    parent=child
                    path.append(parent)
                    break
            
        return parent,active,path
    

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
    
    
    def setUpVulConstraints(self,curr_wfCall_vb,curr_wfCall,rhs,iswchar=False):
        if curr_wfCall in self._func_wr_sites.keys():
            props=self._func_wr_sites[curr_wfCall]
            if props[0] == 'strcpy':
                return self._getVulConstraintsForStrcpy(curr_wfCall_vb,props,rhs)
            if props[0] == 'strcat':
                return self._getVulConstraintsForStrcat(curr_wfCall_vb,props,rhs)
            if props[0] == 'memcpy' or props[0] == 'memmove':
                return self._getVulConstraintsForMemcpy(curr_wfCall_vb,props,rhs,wchar=iswchar)
            if props[0] == 'memset':
                return self._getVulConstraintsForMemset(curr_wfCall_vb,props,rhs,wchar=iswchar)
            if props[0] == 'sprintf':
                return self._getVulConstraintsForSprintf(curr_wfCall_vb,props,rhs)
        
        
    def _getVulConstraintsForSprintf(self,vex,props,rhs):
        func_name,out_str=rhs
        if isinstance(out_str,str):
            dst_size=self._getSRCorDSTsize('sprintf',vex,props,'dst')
            if dst_size:
                if len(out_str) > dst_size:
                    self._vulReports.append('There is a Buffer Overflow in block {} with target function sprintf '.format(vex.addr))
                

    def _getVulConstraintsForMemset(self,vex,props,rhs,wchar=False):
        func_name,num=rhs
        dst_size=self._getSRCorDSTsize('memset',vex,props,'dst',iswhar=wchar)
        if dst_size:
            message='There is a Buffer Overflow in block {} with target function memset '.format(vex.addr)
            if isinstance(num,int):
                if num > dst_size:
                    self._vulReports.append(message)
        else:
            return (num > dst_size,message)
                
            
            
        
    def _getVulConstraintsForMemcpy(self,vex,props,rhs,wchar=False):       
        func_name,limit=rhs
        message='There is a Buffer Overflow in block {0} with target function {1}'.format(vex.addr,props[0])
        if isinstance(limit,int):
            dst_size=self._getSRCorDSTsize('memcpy',vex,props,'dst',iswhar=wchar)
            if dst_size:
                if limit > dst_size:
                    self._vulReports.append(message)   
        else:
            dst_size=self._getSRCorDSTsize('memcpy',vex,props,'dst',iswhar=wchar)
            if src_size and dst_size:
                const=[limit > dst_size]
                return (claripy.And(*const),message)
                
            
    def _getVulConstraintsForStrcpy(self,vex,props,rhs):
        message='There is a Buffer Overflow in block {} with target function strcpy'.format(vex.addr)
        if isinstance(rhs,str):

            dst_size=self._getSRCorDSTsize('strcpy',vex,props,'dst')
            if dst_size:
                len_rhs=len(rhs)
                if len_rhs >  dst_size:
                    self._vulReports.append(message)
        elif len(props) == 3:

            src_size=self._getSRCorDSTsize('strcpy',vex,props,'src')
            dst_size=self._getSRCorDSTsize('strcpy',vex,props,'dst')
            if src_size and dst_size:
                const=[]
                if src_size < dst_size:
                    return None
                
                const.append(claripy.UGT(rhs ,dst_size+1))
                const.append(claripy.ULT(rhs,src_size))
                return (claripy.And(*const),message)
        

    def _getVulConstraintsForStrcat(self,vex,props,rhs):
        func_name,dst_len,src_len=rhs
        message='There is a Buffer Overflow in block {} with target function strcat'.format(vex.addr)
        if isinstance(src_len,int):
            dst_size=self._getSRCorDSTsize('strcat',vex,props,'dst')
            if dst_size:
                return (dst_size - dst_len <  src_len,message)
        else:
            src_size=self._getSRCorDSTsize('strcat',vex,props,'src')
            dst_size=self._getSRCorDSTsize('strcat',vex,props,'dst')
            if src_size and dst_size:
                const=[dst_size - dst_len < src_len , src_len < src_size]
                return (claripy.And(*const),message)
                    
        
        
    def _getSRCorDSTsize(self,func_name,vex,props,arg_type,iswhar=False):
        res_addr=None
        for addr,tp in props[1:]:
            if tp == arg_type:
                res_addr=addr

        if res_addr is None :
            return None
        arg_index=1 if arg_type=='src' else 0
        res_size=self._malloc_boundry[res_addr]
        arg_indexing=self.cfg_Analyzer._trackInputOfFuncionCall(vex,arg_index,self.cfg_Analyzer.getFuncAddress(func_name),just_index=True)
        if arg_indexing is not None:
            res_size=res_size - arg_indexing[1].con.value

        if iswhar:
            res_size=int(res_size/4)
            
        return res_size
        
        
        
        
        
        
        
