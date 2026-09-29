#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jul 26 20:24:03 2020

@author: ali
"""


def is_tainted(state):
    _tainted_regs = []
    if state.regs.rsi.to_claripy().annotations != None:
        _tainted_regs.append("rsi")
    if state.regs.rdi.to_claripy().annotations != None:
        _tainted_regs.append("rdi")
    if state.regs.rsi.to_claripy().annotations != None:
        _tainted_regs.append("rsi")
    if state.regs.rbp.to_claripy().annotations != None:
        _tainted_regs.append("rbp")
    if state.regs.rsp.to_claripy().annotations != None:
        _tainted_regs.append("rsp")
    if state.regs.rip.to_claripy().annotations != None:
        _tainted_regs.append("rip")
    if state.regs.rax.to_claripy().annotations != None:
        _tainted_regs.append("rax")
    if state.regs.rbx.to_claripy().annotations != None:
        _tainted_regs.append("rbx")
    if state.regs.rcx.to_claripy().annotations != None:
        _tainted_regs.append("rcx")
    if state.regs.rdx.to_claripy().annotations != None:
        _tainted_regs.append("rdx")
    if state.regs.r10.to_claripy().annotations != None:
        _tainted_regs.append("r10")
    if state.regs.r12.to_claripy().annotations != None:
        _tainted_regs.append("r12")
    if state.regs.r13.to_claripy().annotations != None:
        _tainted_regs.append("r13")
    if state.regs.r14.to_claripy().annotations != None:
        _tainted_regs.append("r14")
    if state.regs.r15.to_claripy().annotations != None:
        _tainted_regs.append("r15")

    return _tainted_regs


def eval_args(state):

    _regs = is_tainted(state)
    for index,arg in enumerate(_args):
        print("\t\t|--- arg_%s :=> %s " % (index,state.solver.eval(arg, cast_to=bytes)))
    if (_regs != None) and len(_regs) > 0:
        print("\t\t|--- tainted regs : ",end="")
        for reg in _regs:
            print("%s " % (reg),end="")
        print()
    print("\t|-- satisfiable : %s " % (state.satisfiable()))
    print("\t\t|--- stdin :=> %s " % (state.solver.eval(_sym_stdin, cast_to=bytes)))
    print()



----------------------------------------------------------------------------
        funcs_malloc=self.analysis.getAddressOfFunctionCall('malloc')
        funcs_free=self.analysis.getAddressOfFunctionCall('free',True)
        unit=list()
        
        print("\033[91m{} Points was detected \033[00m".format(len(funcs_malloc)))
        for addr,func in funcs_malloc:
            list_item=list()
            unit.append(list_item)
            list_item.append(addr)
            list_item.append(funcs_free[func].pop())
            
            isLoop=False
            
            for i in func.blocks:
                 tmp=self.analysis.isLoopByAddr(i.vex)
                 if tmp[0] == False:
                     continue
                 #document
                 st=self.analysis.storeEffectedByReg(i.vex,'rbp')
                 if st is not None:
                     for item in st:
                         tmp_tar_addr=self.analysis.getAddressStatement(i.vex,item)
                         if tmp_tar_addr > tmp[1] and  tmp_tar_addr < tmp[2]:
                             list_item[1]=tmp[2]
                             isLoop=True
            
            #fixed                 
            if isLoop == False:
                for i in func.blocks:
                    st=self.analysis.storeEffectedByReg(i.vex,'rbp')
                    if st is not None:
                        for item in st:
                            tmp_tar_addr=self.analysis.getAddressStatement(i.vex,item)
                            list_item[1]=tmp_tar_addr
            

        return unit







---------------------------------------------------------------------
    def isRegStore(self,vex,reg_name):
        isWritenWithTargetTemp=False
        target_get=self.listOfWrTmpWithRegName(vex,reg_name)
        if len(target_get) > 0 :
            target_get=target_get[0]
        else:
            return  isWritenWithTargetTemp
        target_tmp_name=target_get.tmp
        result=self.storeEffectedByReg(vex,reg_name)
        for i in result:
            if isinstance(i.data,pyvex.expr.RdTmp):
                if i.data.tmp == target_tmp_name:
                    isWritenWithTargetTemp=True
                    
                    
        return isWritenWithTargetTemp


    
            
            
            