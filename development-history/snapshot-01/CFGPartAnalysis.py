#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jun 11 00:17:30 2020

@author: ali
"""


class CFGPartAnalysis(angr.Analysis):
    
    def __init__(self):
        self.cfg=self.project.analyses.CFGFast(data_references=True)
    
    
    def getFuncAddress(self, funcName, plt=None ):
        found = [
            addr for addr,func in self.cfg.kb.functions.items()
            if funcName == func.name and (plt is None or func.is_plt == plt)
            ]
        if len( found ) > 0:
            #print("Found "+funcName+"'s address at "+hex(found[0])+"!")
            return found[0]
        else:
            raise Exception("No address found for function : "+funcName)
            
    def resolveAddrByFunction(self,addr):
        
        for i in self.getFunctions():
            r=i[1]
            for block in r.blocks:
                if addr in block.instruction_addrs:
                    return r

    def getFunctions(self):
        result=list()
        for addr,func in self.cfg.kb.functions.items():
            result.append((addr,func))
            
        return result
    
    
    def mapAddrToFunctionName(self,targetAddr):
        for addr,func in self.getFunctions():
            for block in func.blocks:
                if targetAddr in block.instruction_addrs:
                    return func.name
                
        return None
    
    def getEndPoint(self,target_name):
        target=self.resolveAddrByFunction(self.getFuncAddress(target_name))
        addr=0x0
        for node in target.endpoints:
            if addr < node.addr:
                addr=node.addr
        
        return  addr
    
    
    def listOfNodesWithLoop(self):
        all_paths=self.getAllPaths(self.cfg.graph)
        index=set()
        for path in all_paths:
            for node in path:
                if node.block is not None: 
                    if CFGPartAnalysis.isLoop(node.block.vex): 
                        index.add((path.index(node),node)) 
                        
        return index
    
    def getCallee(self,func_name):
        result=list()
        functions=self.getFunctions()
        for func in functions:
            call_sites=list(func[1].get_call_sites())
            for site in call_sites:
                block=self.project.factory.block(site)
                vex=block.vex
                if vex.jumpkind == 'Ijk_Call':
                    if len(vex.next.constants) > 0 :
                        addr=vex.next.constants[0].value 
                        if self.cfg.kb.functions[addr].name == func_name:
                            result.append(func)
                            
        return result
    
        
    @staticmethod
    def isLoop(vex):
        exits=list(vex.exit_statements)
        for i in exits:
            stmt=i[2]
            currentAddr=i[0]
            if stmt.jumpkind == 'Ijk_Boring':
                if currentAddr > stmt.dst.value:
                    return True
                elif currentAddr > vex.default_exit_target:
                    return  True
        return False
    
    
    def isLoopByAddr(self,vex):
        exits=list(vex.exit_statements)
        for i in exits:
            stmt=i[2]
            currentAddr=i[0]
            if stmt.jumpkind == 'Ijk_Boring':
                if currentAddr > stmt.dst.value:
                    return (True,stmt.dst.value,currentAddr)
                elif currentAddr > vex.default_exit_target:
                    return (True, vex.default_exit_target,currentAddr)
        
        return (False,)
    
    def getLoopsInFunction(self,func):
        target_func=self.resolveAddrByFunction(self.getFuncAddress(func))
        result=list()
        for block in target_func.blocks:
            loopSite=self.isLoopByAddr(block.vex)
            if loopSite[0] == False:
                continue
            if loopSite not in result:
                result.append(loopSite)
        return result
    
    
    
    def getCFGFast(self):
        return self.cfg
                
    def getAllPaths(self,G):
        roots = (v for v, d in G.in_degree() if d == 0)
        leaves = [v for v, d in G.out_degree() if d == 0]
        all_paths = []
        for root in roots:
            paths = np.all_simple_paths(G, root, leaves)
            all_paths.extend(paths)
            
        return all_paths

    def listOfTempStmt(self,v,target):
        import re
        result=list()
        for i in v.statements:
            tmp=i.__str__()
            if re.match(".*"+target+"\\D.*|.*"+target +"$",tmp) is None:
                continue
            result.append(i)
        return result



    def getVexListCommand(self,vex,vexType):
        result=list()
        for i in vex.statements:
            if isinstance(i,vexType):
                result.append(i)

                    
        return result


    def getRegsName(self,vex,offset):
        for  j in vex.arch.register_list: 
            if offset is j.vex_offset:
                 return j.name
             
                
    def getRegOffset(self,vex,reg_name):
        for  j in vex.arch.register_list: 
            if j.name == reg_name:
                return j.vex_offset 

    def listOfWrTmpWithRegName(self,vex,reg_name):
        tmp=self.getVexListCommand(vex,pyvex.IRStmt.WrTmp)
        getList=list()
        for i in tmp:
            if i.data.tag == 'Iex_Get':
                getList.append(i)
    
        result=list()
        for i in getList:
            offset=i.data.offset
            name=self.getRegsName(vex,offset)
            if reg_name == name:
                result.append(i)
                
        del(getList)
        return result
    
    def getBlockOfFunctionAt(self,func_name,at):
        func=self.resolveAddrByFunction(self.getFuncAddress(func_name))
        result=list()
        for  item in func.blocks:
            result.append(item)
        
        return result[at]
    
    def listOfEffectedTmpWithTargetTemp(self,vex,tmp_name):
        tmp=self.listOfTempStmt(vex,tmp_name)
        result=list()
        for i in tmp:
            if isinstance(i,pyvex.IRStmt.WrTmp):
                if 't'+str(i.tmp) != tmp_name:
                    result.append('t'+str(i.tmp))
            if isinstance(i,pyvex.IRStmt.Store):
                if isinstance(i.data,pyvex.expr.RdTmp):
                    if 't'+str(i.data.tmp) == tmp_name: 
                        if isinstance(i.addr,pyvex.expr.RdTmp):
                            result.append('t'+str(i.addr.tmp))
            #add for put
        return result
    
    
    
    
    def targetWrTempByTempName(self,vex,tmp_name):
        tmp=self.listOfTempStmt(vex,tmp_name)
        result=None
        for i in tmp:
            if isinstance(i,pyvex.IRStmt.WrTmp):
                if 't'+str(i.tmp) == tmp_name:
                    result=i
        
        return result
    
    def listOfEffectedTempBy(self,vex,tmp_name):
        effected=self.listOfEffectedTmpWithTargetTemp(vex,tmp_name)
        target=effected.copy()
        blocklist=list()
        while len(target) > 0:
            i=target.pop()
            blocklist.append(i)
            tmp=self.listOfEffectedTmpWithTargetTemp(vex,i)
            for item in tmp:
                if item not in effected:
                    effected.append(item)
                if item not in blocklist and item not in target:
                    target.append(item)
                    blocklist.append(item)
        del(blocklist)     
      
        return effected
    
    
    def storeEffectedByReg(self,vex,reg_name):
        reg_wr=self.listOfWrTmpWithRegName(vex,reg_name)
        if len(reg_wr) > 0:
            reg_wr=reg_wr[0]
        else:
            return None
        temp_name='t'+str(reg_wr.tmp)
        effected_temps=self.listOfEffectedTempBy(vex,temp_name)
        stores=self.getVexListCommand(vex,pyvex.IRStmt.Store)
        result=list()
        if len(stores) > 0:
            for item in stores:
                if isinstance(item.addr,pyvex.IRExpr.RdTmp):
                    target='t'+str(item.addr.tmp)
                    if target in effected_temps:
                        result.append(item)
                        
        return result
    
    
    def getAddressStatement(self,vex,stmt):
        addr=None
        for i in vex.statements:
            if isinstance(i,pyvex.IRStmt.IMark):
                addr=i.addr
            if stmt is i:
                return addr
            
        return None
        
    
    



    def getAddressOfFunctionCall(self,func_name,dict_type=False):
        if dict_type:
            result=dict()
        else:
            result=set()
        callees=self.getCallee(func_name)
        if len(callees)>0:
            for func in callees:
                addr=self.getFuncAddress(func_name)
                for i in func[1].blocks:
                    tmp_vex=i.vex
                    if tmp_vex.jumpkind == 'Ijk_Call':
                        if addr in tmp_vex.constant_jump_targets:
                            if dict_type:
                                key=func[1]
                                value=tmp_vex.instruction_addresses[len(tmp_vex.instruction_addresses)-1]
                                if key not in result.keys():
                                    result[key]=list()
                                if value not in result[key]:
                                    result[key].append(value)
                                
                            else:
                                result.add((tmp_vex.instruction_addresses[len(tmp_vex.instruction_addresses)-1],func[1]))
        if dict_type:
            return result
        return list(result)
    
    
    def getBlockOFFuctionCall(self,callee_name,caller_name):
        addrs=self.getAddressOfFunctionCall(callee_name)
        if len(addrs) == 0:
            return None
        result=list()
        for item in addrs:
            addr,caller=item
            if caller.name == caller_name:
                for i in caller.blocks:
                    if addr in i.instruction_addrs:
                        result.append(i)
    
        return result

    
    
    

    def getDSTOfRAX(self,vex):
        '''
        take an vex block and return
        ('rbp:t4', <pyvex.expr.Const at 0x7fd09da76eb8>, 'Iop_Add64')
        where const is location which deffer from rbp in stack 
        it means :
            t=add64(rbp,const)
            store(t)=rax or eax
        '''
        rax_tmp=self.listOfWrTmpWithRegName(vex,'rax')
        if len(rax_tmp) == 0:
            return None
        else:
            rax_tmp=rax_tmp[0].tmp
        rbp_tmp=self.listOfWrTmpWithRegName(vex,'rbp')
        if len(rbp_tmp) == 0:
            return None
        else:
            rbp_tmp=rbp_tmp[0].tmp
            
        effected_rax=self.listOfEffectedTmpWithTargetTemp(vex,'t'+str(rax_tmp))
        undirectEAX=list()
        if len(effected_rax)==1:
            tmp_tmp=effected_rax[0]
            tmp_stmt=self.targetWrTempByTempName(vex,tmp_tmp)
            if isinstance(tmp_stmt,pyvex.IRStmt.WrTmp):
                if isinstance(tmp_stmt.data, pyvex.expr.Unop) and tmp_stmt.data.op == 'Iop_64to32':
                    undirectEAX.append(tmp_tmp)
                    for i in self.listOfEffectedTmpWithTargetTemp(vex,tmp_tmp):
                        undirectEAX.append(i)
                             
        target_store=None
        for i in self.getVexListCommand(vex,pyvex.IRStmt.Store):
            if isinstance(i.data,pyvex.expr.RdTmp):
                if i.data.tmp==rax_tmp or ('t'+str(i.data.tmp) in undirectEAX):
                    target_store=i

        
        result=None
        if target_store is not None:
            dst_store=target_store.addr.tmp
            target_cmd=self.targetWrTempByTempName(vex,'t'+str(dst_store))
            if isinstance(target_cmd.data,pyvex.expr.Binop):
                if 'Iop_Add' in target_cmd.data.op or 'Iop_Sub' in target_cmd.data.op:
                    tmp_var=target_cmd.data.args[0].tmp
                    if tmp_var == rbp_tmp:
                        result=('rbp:t'+str(rbp_tmp),target_cmd.data.args[1],target_cmd.data.op)
        
        return result
    
    
    
    def getRetStoreLocOnStackOfFunction(self,callee,caller):
        '''
        this function return places in stack where return value of callee is store ,if there is one.
        return's' :
            {0x400818: ('rbp:t4', <pyvex.expr.Const at 0x7fd09da76eb8>, 'Iop_Add64')}
            0x400818 -> where called is called
            ('rbp:t4', <pyvex.expr.Const at 0x7fd09da76eb8>, 'Iop_Add64') -> where in stack is retured value store.
            
            
        '''
        result=list()
        called=False
        func_loc=None
        caller=self.resolveAddrByFunction(an.getFuncAddress(caller))
        for i in caller.blocks:
            vex=i.vex
            addr=self.getFuncAddress(callee)
            if called:
                tmp_r=dict()
                tmp_r[func_loc]=self.getDSTOfRAX(vex)
                result.append(tmp_r)
                called=False
                func_loc=None
            if addr in vex.constant_jump_targets_and_jumpkinds.keys():
                called=True
                func_loc=vex.instruction_addresses[len(vex.instruction_addresses)-1]
        return result
    
    def _getLastPutStmtByOffset(self,vex,offset):
        puts=self.getVexListCommand(vex,pyvex.IRStmt.Put)
        puts.reverse()
        for i in puts:
            if i.offset == offset:
                return i
        
        return None
    
    def _getListPutStmtByRegName(self,vex,reg_name):
        result=list()
        puts=self.getVexListCommand(vex,pyvex.IRStmt.Put)
        for i in puts:
            if i.offset == self.getRegOffset(vex,reg_name):
                result.append(i)
                
        return result
    
    def trackInputOfFuncionCall(self,vex,input_number,target_fAddr):
        '''
            this function takes an vex block and check target function is called in that block
            and extracted regcc where used and copies values into before function call
            where input_number show which argcc we intersted in.
            
            first for every regcc checks:
            puts(regcc)=t --> t=(add or sub)(rbp,cons)
            where t return in bio operation where one side of it is rbp register which means a location of stack copies in regcc
            or second
            it check effected list of rbp where bio operation exist and extract left side bio opr
            then extract effected list of left side and check t i in the list if yes it ok.
            and  thrid possibility is when we copy an constand in to regcc
            
            return :
                ('rdi', <pyvex.expr.Const at 0x7fd09daa5108>, 'Iop_Add64')
                copy in rdi value of add(rbp,cons) 
            
        '''
        if target_fAddr not in vex.constant_jump_targets_and_jumpkinds.keys() or vex.constant_jump_targets_and_jumpkinds[target_fAddr] != 'Ijk_Call':
            print('Not Found, There is No Such Function Call In This Block ')
            return None

        rbp_tmp=self.listOfWrTmpWithRegName(vex,'rbp')
        if len(rbp_tmp) == 0:
            return None
        else:
            rbp_tmp=rbp_tmp[0].tmp
        result=None
        
        for i in self.getVexListCommand(vex,pyvex.IRStmt.Put):
            cc_arg=self.project.factory.cc().ARG_REGS[input_number]
            if self.getRegsName(vex,i.offset) is  cc_arg: 
                if isinstance(i.data,pyvex.expr.RdTmp):
                    target_tmp=i.data.tmp
                    wr_target=self.targetWrTempByTempName(vex,'t'+str(target_tmp))
                    if isinstance(wr_target.data,pyvex.expr.Binop ):
                        if 'Iop_Add' in wr_target.data.op or 'Iop_Sub' in wr_target.data.op:
                            tmp_var=wr_target.data.args[0].tmp
                            if tmp_var == rbp_tmp:
                                result=(cc_arg,wr_target.data.args[1],wr_target.data.op)
                    else:
                        #this part has problem
                         rbp_effected=self.listOfEffectedTmpWithTargetTemp(vex,'t'+str(rbp_tmp))
                         rbp_effected.append('t'+str(rbp_tmp))
                         
                         bio_opr=[]
                         for i in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                             if isinstance(i.data,pyvex.expr.Binop):
                                 if 't'+str(i.data.args[0].tmp) in rbp_effected:
                                     bio_opr.append(i)
                        
                                                 
                         if isinstance(wr_target.data,pyvex.expr.Load):
                             if isinstance(wr_target.data.addr,pyvex.expr.RdTmp):
                                 load_src=wr_target.data.addr.tmp
                                 for bio in bio_opr:
                                     bio_arg1=bio.tmp
                                     bio_arg1_effected=self.listOfEffectedTempBy(vex,'t'+str(bio_arg1))
                                     if load_src == bio_arg1 or 't'+str(bio_arg1) in bio_arg1_effected:
                                         result=(cc_arg,bio.data.args[1],bio.data.op)
                                         break
                                 
                                         
                elif isinstance(i.data,pyvex.expr.Const):
                    if self._getLastPutStmtByOffset(vex,i.offset) is i:
                        result=(cc_arg,i.data,i.data.tag)
        return result
    
    
    def getArgsCC(self,vex,target_fAddr):
        '''
         this funcion try to extract all argcc where a value is copied into before calling target function
         
         warrning: this doesn't mean all argcc are argument of function in the target function we must check
        '''
        result=list()
        for i in range(0,len(proj.factory.cc().ARG_REGS)): 
            tmp_ret=self.trackInputOfFuncionCall(vex,i,target_fAddr)
            if tmp_ret is not None :
                if len(result) == 0:
                    result.append(tmp_ret)
                else:
                    flag=True
                    for item in result:
                        if (item[1].con.value == tmp_ret[1].con.value) and item[2] ==tmp_ret[2]:
                            flag=False
                            break
                    if flag:
                        result.append(tmp_ret)


        return result
    
    
    #inja bayad check koni chandta malloc ha copy mishe
    
    
    def mallocRetCopyToARGCC(self,vex,callee,caller):
        '''
        after getting argcc of callee we check and return argc who malloc return value is copied into.
        vex argument is vex block of where callee called(getBlockOFFunctionCall(callee))
        '''
        args_cc=self.getArgsCC(vex,self.getFuncAddress(callee))
        rax=self.getRetStoreLocOnStackOfFunction('malloc',caller)
        result=list()
        for i in rax:
            for addr,rx in i.items():
                for cc in args_cc:
                    if (rx[1].con.value == cc[1].con.value) and rx[2]==cc[2]:
                        result.append(cc)
                    
        return result


    
    def trackREGCCinCallee(self,caller,callee,callblock,targetRegCC=None):
        '''
            track if reg cc (that malloc return value is copy to it) store in zero block of calle
            return:
                ('rdi', <pyvex.expr.Const at 0x7f8a1c8f6a08>, 'Iop_Add64')
                where rdi is store in const location relative to rbp register in callee function
        '''

        if callblock  is  None:
            return None 
        
        if targetRegCC is None:
            r=self.mallocRetCopyToARGCC(callblock.vex,callee,caller)
        else:
            r=targetRegCC
            
        if len(r) == 0:
            return None
        
        regs=list()
        for i in r:
            regs.append(i[0])
        t=self.getBlockOfFunctionAt(callee,0)
        rbp_tmp=self.listOfWrTmpWithRegName(t.vex,'rbp')
        if len(rbp_tmp) == 0:
            return None
        else:
            rbp_tmp=rbp_tmp[0].tmp
        
        temps_get=list()
        for i in regs:
            tmp=self.listOfWrTmpWithRegName(t.vex,i)
            for item in tmp:
                temps_get.append('t'+str(item.tmp))
        
        result=list()
        for i in regs:
            stores=self.storeEffectedByReg(t.vex,i)
            for item in stores:
                if isinstance(item.data,pyvex.expr.RdTmp):
                    tmp_var='t'+str(item.data.tmp)
                    if tmp_var in temps_get:
                        if isinstance(item.addr,pyvex.expr.RdTmp):
                            addr_tmp_var='t'+str(item.addr.tmp)
                            target=self.targetWrTempByTempName(t.vex,addr_tmp_var)
                            if isinstance(target.data,pyvex.expr.Binop ) and 'Iop_Add' in target.data.op or 'Iop_Sub' in target.data.op:
                                effected_rbp=self.listOfEffectedTempBy(t.vex,'t'+str(rbp_tmp))
                                tmp_var='t'+str(target.data.args[0].tmp)
                                if (tmp_var in effected_rbp) or (tmp_var == 't'+str(rbp_tmp)):
                                    result.append((i,target.data.args[1],target.data.op))


        return result


    def _listOfStoreWithTempNameDst(self,vex,tmp_name):
        result=list()
        for i in self.getVexListCommand(vex,pyvex.IRStmt.Store):
            if isinstance(i.addr,pyvex.expr.RdTmp):
                addr_tmp='t'+str(i.addr.tmp)
                if addr_tmp == tmp_name:
                    result.append(i)
        
        return result
    
    def _listOfLoadwithTempNameSrc(self,vex,tmp_name):
        result=list()
        for i in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
            if isinstance(i.data,pyvex.expr.Load): 
                load_src_tmp='t'+str(i.data.addr.tmp)
                if load_src_tmp == tmp_name:
                    result.append(i)
                    
        return result
    
    def isWriteInAddrHeapRelativeWithRBP(self,vex,dst_addr):
        '''
        track is an write into location dest_addr relative with rbp in stack
        '''
        rbp_tmp=self.listOfWrTmpWithRegName(vex,'rbp')
        if len(rbp_tmp) == 0:
            return None
        else:
            rbp_tmp='t'+str(rbp_tmp[0].tmp)

        bios=list()
        for i in vex.statements:
            if isinstance(i,pyvex.IRStmt.WrTmp):
                if isinstance(i.data,pyvex.expr.Binop):
                    if ('Iop_Add' in i.data.op) or ('Iop_Sub' in i.data.op):
                       bios.append(i)

        for bio in bios:
            if isinstance(bio.data.args[0],pyvex.expr.RdTmp) and isinstance(bio.data.args[1],pyvex.expr.Const):
                tmp='t'+str(bio.data.args[0].tmp)
                addr=bio.data.args[1].con.value
                if tmp == rbp_tmp and addr == dst_addr:
                    loads=self._listOfLoadwithTempNameSrc(vex,'t'+str(bio.tmp))
                    if len(loads) > 0:
                        for load in loads:
                            load_effected_list=self.listOfEffectedTmpWithTargetTemp(vex,'t'+str(load.tmp))
                            load_effected_list.append('t'+str(load.tmp))
                            stores=self.storeEffectedByReg(vex,'rbp')
                            
                            for store in stores:
                                if isinstance(store.addr,pyvex.expr.RdTmp):
                                    if 't'+str(store.addr.tmp) in load_effected_list:
                                        return self.getAddressStatement(vex,store)

        return None
    
    
    
    
    def trackWriteIntoARGCCINCallee(self,callee,argcc):
        '''
        track in callee that is store in register cc in argc
        argc=(reg_name,const,opr)
        
        Returns
        -------
            address of store and block of that store

        '''
        callee_func=self.resolveAddrByFunction(self.getFuncAddress(callee)) 
        result=list()
        for blck in callee_func.blocks:
            rbp_addr=argcc[1].con.value
            wr_addr=self.isWriteInAddrHeapRelativeWithRBP(blck.vex,rbp_addr)
            if wr_addr is not None:
                result.append(wr_addr)
                
                
        return result
            
            
            
    def getFunctionCalledBetweenBoundry(self,caller,start_addr,end_addr):
        '''
        return functions called between start address and end address in caller function
        '''
        caller=self.resolveAddrByFunction(self.getFuncAddress(caller)) 
        start_discover=False
        result=list()
        for i in caller.blocks:
            if ~start_discover:
                if start_addr in i.instruction_addrs:
                    start_discover=True
            if start_discover:
                if end_addr in i.instruction_addrs:
                    return result
                else:
                    if i.vex.jumpkind=='Ijk_Call':
                        for addr,kind in i.vex.constant_jump_targets_and_jumpkinds.items():
                            if kind=='Ijk_Call':
                                func=self.resolveAddrByFunction(addr)
                                result.append((addr,func.name))
        return result
    
    def remvoeSTLFunctionInList(self,func_list):
        '''
            remove simprocedure functions in above list
        '''
        remove_list=list()
        for i in angr.SIM_PROCEDURES.keys():
            for j  in func_list:
                if j[1]  in  angr.SIM_PROCEDURES[i].keys():
                    remove_list.append(j)

        

        for rm in remove_list:
                func_list.remove(rm)
               
        del(remove_list)
        return func_list
                
    
    def isWriteHappendInBoundry(self,caller,start_addr,end_addr,addr):
        '''
            determined is write intor this address between this boundry
        '''
        caller=self.resolveAddrByFunction(self.getFuncAddress(caller)) 
        start_discover=False
        end_discover=False
        result=list()
        for i in caller.blocks:
            if start_discover == False:
                if start_addr in i.instruction_addrs:
                    start_discover=True
            if start_discover:
                if end_addr in i.instruction_addrs:
                    end_discover=True
                    
                dst=self.isWriteInAddrHeapRelativeWithRBP(i.vex,addr)
                if dst is not None:
                    result.append(dst)
                
                if end_discover == True:
                    return result
        return result
                        
        
    def  _mapAddrOfMallocInCallerAndCalle(self,callee,caller,reversed=None,whole=False):
        if whole:
            result=list()
        else:
            result=dict()
        for callBlock in self.getBlockOFFuctionCall(callee,caller):
            for mr in self.mallocRetCopyToARGCC(callBlock.vex,callee,caller):
                for regcc in self.trackREGCCinCallee(caller,callee,callBlock):
                    if mr[0] == regcc[0]:
                        if whole:
                            result.append(regcc)
                        else:
                            if reversed is None:
                                result[mr[1].con.value]=regcc[1].con.value
                            else:
                                result[regcc[1].con.value]=mr[1].con.value

        return result
    
    def _mapRegccInCalleeAndCaller(self,caller,callee,caller_regcc):
        result=[]
        for callBlock in self.getBlockOFFuctionCall(callee,caller):
            input_callee=[]
            callee_argcc=self.getArgsCC(callBlock.vex,self.getFuncAddress(callee))
            for caller_arc in caller_regcc:
                for callee_arc in callee_argcc:
                    if caller_arc[1].con.value == callee_arc[1].con.value:
                        if callee_arc not in input_callee:
                            input_callee.append(callee_arc)
            map=self.trackREGCCinCallee(caller,callee,callBlock,targetRegCC=input_callee)
            result.append((callBlock.addr,map))
        return result
