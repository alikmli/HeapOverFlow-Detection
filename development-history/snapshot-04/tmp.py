#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jul 26 20:24:03 2020

@author: ali
"""

 def _copy(self,items,system=True,unitArgsStatus=None,justcopy=False):
        res=[]
        if justcopy :
            for item in items:
                res.append(item.copy())
            return res
        
        if unitArgsStatus is None :
            indxes=self._mc._mapTypeToVarIndex('char')
            for item in items:
                tmp=item.copy()
                for idx in indxes:
                    tmp[idx]=ord(tmp[idx])
                res.append(tmp)
        else:
            indxes=[]
            remove_indexes=[]
            if system :
                for indx in range(len(self._mc._types)):
                    typ=self._mc._types[indx]
                    if isinstance(typ,tuple) and typ[0] == 'char*':
                        remove_indexes.append(indx)
                    elif 'char' in typ:
                        indxes.append(indx)
            else:
                for indx,typ in unitArgsStatus.items():
                    if 'charPointer' in typ:
                        remove_indexes.append(indx-1)
                    elif 'char' in typ:
                        indxes.append(indx-1)
            
            for item in items:
                tmp=item.copy()
                tmp_res=[]
                for tmp_indx in range(len(tmp)):
                    if tmp_indx in indxes:
                        tmp_res.append(ord(tmp[tmp_indx]))
                    
                    elif tmp_indx in remove_indexes:
                        string=tmp[tmp_indx]
                        positions=self._getPosForVarBaseCharStar(tmp_indx+1)
                        if len(positions) > 0:
                            for pos in positions:
                                tmp_res.append(ord(string[pos]))
                    else:
                        tmp_res.append(tmp[tmp_indx])
                res.append(tmp_res)    
        return res
    
    
    


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


    
            
            
            