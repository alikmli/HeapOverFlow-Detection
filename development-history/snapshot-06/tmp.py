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


----------------------------------------------------------------------------
    ##################################################################
    
    def getStRelatedFixArgsFor(self,func_name,vex):
        """
            it follow writes into stack and checks if these writes are
            copied  into function argcc argumnet or not (in the middle some operation like shl64
            might be occurred  but the effect is not extracted)
        """
        rbp_tmp=self.listOfWrTmpWithRegName(vex,'rbp')
        result=[]
        if len(rbp_tmp) > 0:
            rbp_tmp='t'+str(rbp_tmp[0].tmp)
            bio_cmd=[]
            for i in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                if isinstance(i.data,pyvex.expr.Binop):
                    if isinstance(i.data.args[0],pyvex.expr.RdTmp) and str(i.data.args[0]) == rbp_tmp:
                        bio_cmd.append(i)
            
            for bio in bio_cmd:
                if isinstance(bio.data.args[1],pyvex.expr.Const):
                    for addr,value in self.getSimpleWrINStackFor(func_name):
                        bio_addr=bio.data.args[1].con.value
                        if addr.con.value == bio_addr:
                            target_tmp='t'+str(bio.tmp)
                            for load in self._listOfLoadwithTempNameSrc(vex,target_tmp):
                                load_tmp='t'+str(load.tmp)
                                load_effected=self.listOfEffectedTempBy(vex,load_tmp)
                                load_effected.append(load_tmp)
                                for argc in self.project.factory.cc().ARG_REGS:
                                    put=self._getLastPutStmtByOffset(vex,self.getRegOffset(vex,argc))
                                    if put is not None :
                                        if isinstance(put.data,pyvex.expr.RdTmp):
                                            put_tmp = str(put.data)
                                            tmp_res=(argc,value)
                                            if put_tmp in load_effected and tmp_res not in result:
                                                result.append(tmp_res)
            
        for argc in self.project.factory.cc().ARG_REGS:
            put=self._getLastPutStmtByOffset(vex,self.getRegOffset(vex,argc))
            if put is not None and isinstance(put.data,pyvex.expr.Const):
                tmp_res=(argc,put.data.con.value)
                if  tmp_res not in result:
                    result.append(tmp_res)
            

                                            
        return result

    
    
    def getSimpleWrINStackFor(self,func_name):
        func=self.resolveAddrByFunction(self.getFuncAddress(func_name))
        result=[]
        for blck in func.blocks:
            result.extend(self._getWritesInStack(blck.vex))
            
        return result
    
    def _getWritesInStack(self,vex):
        rbp_tmp=self.listOfWrTmpWithRegName(vex,'rbp')
        result=[]
        if len(rbp_tmp) == 0:
            return result
        else:
            rbp_tmp=rbp_tmp[0].tmp
        
        for i in self.getVexListCommand(vex,pyvex.IRStmt.Store):
            if isinstance(i.data,pyvex.expr.Const) and isinstance(i.addr,pyvex.expr.RdTmp):
                src_tmp=str(i.addr)
                wr_target=self.targetWrTempByTempName(vex,src_tmp)
                if isinstance(wr_target,pyvex.stmt.WrTmp) and isinstance(wr_target.data,pyvex.expr.Binop):
                    lhs=wr_target.data.args[0]
                    rhs=wr_target.data.args[1]
                    if isinstance(lhs,pyvex.expr.RdTmp):
                        rbp_put=self._getLastPutStmtByOffset(vex,self.getRegOffset(vex,'rbp'))
                        if rbp_put is not None:
                            if self.getAddressStatement(vex,rbp_put) < self.getAddressStatement(vex,wr_target):
                                if isinstance(rbp_put.data,pyvex.expr.RdTmp):
                                    tmp_put=str(rbp_put.data)
                                    if (str(lhs) == tmp_put) or (str(lhs) == 't'+str(rbp_tmp)):
                                        val=i.data.con.value
                                        if val in range(self.project.loader.min_addr,self.project.loader.max_addr):
                                            str_len=self._est_str_length(val)
                                            val=self.project.loader.memory.load(val,str_len)
                                        result.append( (rhs,val))
                        elif str(lhs) == 't'+str(rbp_tmp):
                            val=i.data.con.value
                            if val in range(self.project.loader.min_addr,self.project.loader.max_addr):
                                str_len=self._est_str_length(val)
                                val=self.project.loader.memory.load(val,str_len)
                            result.append( (rhs,val))
        return result

    
    def _est_str_length(self,addr):
        length=1
        while True:
            if self.project.loader.memory.load(addr,length)[-1] is 0:
                break
            length=length+1
        return length
    
    ###########################################################3
            
            
            