#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

Created on Mon Jul 13 16:59:10 2020

@author: ali

"""


class Units:
    
    def __init__(self,valAnalysis):
        self._analysis=valAnalysis
        self._maps={}
        
        
    def getUnitForHeapBufferOverFlow(self):
        result=[]
        for addr , func in self._analysis.getCaller('malloc'):
            begin=func.startpoint.addr
            end=self._analysis.getEndPoint(func.name)
            
            malloc_pro=dict()
            funcs_malloc=self._analysis.getAddressOfFunctionCall('malloc')
            for i in self._analysis.getRetStoreLocOnStackOfFunction('malloc',func.name):
                for addr,value in i.items():
                    for item in funcs_malloc:
                        if item[0] == addr and item[1].name == func.name:
                            malloc_pro[addr]=value
                        
            for addr,argcc in malloc_pro.items():
                if addr not in self._maps.keys():
                    self._maps[addr]=[(func.name,argcc)]
                        
            for addr,argc in malloc_pro.items():
                tmp_res=self._checkForDengrouseFunction(func.name,argc)
                for item in tmp_res:
                    if len(item)>0:
                        result.append((addr,func.name,item))
                
            #TODO : check free is called in callee function or in functions called
            wr_res=self._checkIsWriteInTargetFunction(func.name,malloc_pro,target_name=func.name)
            if len(wr_res) > 0 :       
                result.extend(wr_res)
            
            funcs=self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(func.name,begin,end))
            for f_addr,f_name in funcs:
                for callblock in self._analysis.getBlockOFFuctionCall(f_name,func.name):
                    refined_malloc=self._getRefinedMallocProForFunc(callblock,func.name,malloc_pro)
                    for item in self._getUnitsForOnBlocks(func.name,f_name,refined_malloc):
                        if item not in result:
                            result.append(item)                
        return result
    
    
    def _getRefinedMallocProForFunc(self,callblock,caller,old_malloc):
        new_malloc={}
        for addr , value in old_malloc.items():
            if self._isValidAddress(callblock,caller,value):
                new_malloc[addr]=value
        return new_malloc
    
    
    
    def _getUnitsForOnBlocks(self,caller,callee_name,malloc_pro):
        #getting malloc addresses
        unit_list=list()
        if len(malloc_pro) ==0 : 
            return malloc_pro
        
            
        call_chains=self._getCallChain(callee_name)
        argcc=self._analysis._mapAddrOfMallocInCallerAndCalle(callee_name,caller,whole=True)
        key_maps=self._analysis._mapAddrOfMallocInCallerAndCalle(callee_name,caller)
        for addr,argc in self.searchInMaps(caller):
            key=argc[1].con.value
            if key in key_maps.keys():
                value=key_maps[key]
                for argc in argcc:
                    if argc[1].con.value==value:
                        if self._isINMap(addr,callee_name,argc) == False:
                            self._maps[addr].append((callee_name,argc))
                            break

        for chain in call_chains:
            chain_caller,chain_callee=chain
            for addr,argc in self.searchInMaps(chain_caller):
                res=self._analysis._mapRegccInCalleeAndCaller(chain_caller,chain_callee,[argc])[0][1]
                if res is not None :
                    if self._isINMap(addr,chain_callee,res[0]) == False:
                        self._maps[addr].append((chain_callee,res[0]))
        
        for addr,items in self._maps.items():
            for func_name,argcc in items:
                if func_name == caller:continue
                res=self._analysis.trackWriteIntoARGCCINCallee(func_name,argcc)
                tmp_res=self._checkForDengrouseFunction(func_name,argcc)
                for item in tmp_res:
                    if len(item)>0:
                        unit_list.append((addr,func_name,item))
                if len(res)>0:
                    unit_list.append((addr,func_name,res))


        return unit_list
    
    
    def  _isINMap(self,addr,callee_name,argc):
        target=self._maps[addr]
        for func_name,t_argc in target:
            if func_name == callee_name:
                if argc[0] == t_argc[0] and argc[1].con.value == t_argc[1].con.value and argc[2] == t_argc[2]:
                        return True
        return False
            
            
            
    def _checkForDengrouseFunction(self,caller,argcaller):
        dgrFunctions=['strcpy','strcat','memcpy','memset','memmove','sprintf']
        result=[]
        tmp_res=self._checkForStrFuncs('strcpy',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
            
        tmp_res=self._checkForStrFuncs('strcat',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
        
        tmp_res=self._checkForMEMStrFuncs('memcpy',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
            
        tmp_res=self._checkForMEMStrFuncs('memmove',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
        
        tmp_res=self._checkForMEMStrFuncs('memset',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
            
        tmp_res=self._checkForSprintf('sprintf',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
            
        return result
        
    
    
    def _checkForSprintf(self,func_name,caller,argcaller):
        func_callblock=self._analysis.getBlockOFFuctionCall(func_name,caller)
        if func_callblock is None:
            return 
        
        result=[]
        dst_argc=self._analysis.project.factory.cc().ARG_REGS[0]
        for callblock in func_callblock:
            for argc in self._analysis.getArgsCC(callblock.vex,self._analysis.getFuncAddress(func_name)):
                if argc[1].con.value == argcaller[1].con.value and argc[0] == dst_argc:
                    result.append((func_name,callblock.instruction_addrs[-1],'dst') )
                    
        return result
    
    
    
    
    def _checkForMEMStrFuncs(self,func_name,caller,argcaller):
        func_callblock=self._analysis.getBlockOFFuctionCall(func_name,caller)
        if func_callblock is None:
            return 
        
        result=[]
        dst_argc=self._analysis.project.factory.cc().ARG_REGS[0]
        src_argc=self._analysis.project.factory.cc().ARG_REGS[1]
        len_argc=self._analysis.project.factory.cc().ARG_REGS[2]
        for callblock in func_callblock:
            for argc in self._analysis.getArgsCC(callblock.vex,self._analysis.getFuncAddress(func_name)):
                if argc[1].con.value == argcaller[1].con.value and argc[0] == dst_argc:
                    result.append((func_name,callblock.instruction_addrs[-1],'dst') )
                if argc[1].con.value == argcaller[1].con.value and argc[0] == src_argc:
                    result.append((func_name,callblock.instruction_addrs[-1],'src') )
                if argc[1].con.value == argcaller[1].con.value and argc[0] == len_argc:
                    result.append((func_name,callblock.instruction_addrs[-1],'copy_len') )
                    
        return result
    
    
    def _checkForStrFuncs(self,func_name,caller,argcaller):
        func_callblocks=self._analysis.getBlockOFFuctionCall(func_name,caller)
        if func_callblocks is None:
            return 
        
        result=[]
        dst_argc=self._analysis.project.factory.cc().ARG_REGS[0]
        src_argc=self._analysis.project.factory.cc().ARG_REGS[1]
        for callblock in func_callblocks:
            for argc in self._analysis.getArgsCC(callblock.vex,self._analysis.getFuncAddress(func_name)):
                if argc[1].con.value == argcaller[1].con.value and argc[0] == dst_argc:
                    result.append((func_name,callblock.instruction_addrs[-1],'dst') )
                if argc[1].con.value == argcaller[1].con.value and argc[0] == src_argc:
                    result.append((func_name,callblock.instruction_addrs[-1],'src') )
        return result

    
            
    def _isValidAddress(self,callback,caller,value):
        callee=None
        if callback.vex.jumpkind == 'Ijk_Call':
            callee_addr=callback.vex.constant_jump_targets.copy().pop()
            callee=self._analysis.resolveAddrByFunction(callee_addr).name
        if callee is None:
            raise ValueError('Not Valid Callblock')
        
        for reg,con,opr in self._analysis.mallocRetCopyToARGCC(callback.vex,callee,caller):
            if con.con.value == value[1].con.value:
                return True
        return False
        
    def _getCallChain(self,caller):
        result=[]
        uncheckedList=[]

        
        while True:
            main_func=self._analysis.resolveAddrByFunction(self._analysis.getFuncAddress(caller))
            begin=main_func.startpoint.addr
            end=self._analysis.getEndPoint(caller)
            funcs=self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(caller,begin,end))
            
            for func in funcs:
                tmp_res=(caller,func[1])
                if tmp_res not in result:
                    result.append(tmp_res)
                    uncheckedList.append(func[1])
            
            if len(uncheckedList) == 0:
                break
            caller=uncheckedList.pop()
             
      
        return result
    
    
    def searchInMaps(self,target_name):
        res=[]
        for addr,items in self._maps.items():
            for name,_argcc in items:
                if name==target_name:
                    res.append((addr,_argcc))
        return res

    
    
    
    def _checkIsWriteInTargetFunction(self,caller,malloc_pro,target_name=None,target_func=None):
        wr_points=[]
        if target_name is not None:
            if caller  == target_name:
                for addr ,argcc in malloc_pro.items(): 
                    tmp_wr=self._analysis.trackWriteIntoARGCCINCallee(caller,argcc)
                    if len(tmp_wr) > 0 :
                        #tmp_res=(target_name,tmp_wr,addr)
                        tmp_res=(addr,target_name,tmp_wr)
                        wr_points.append(tmp_res)
                
        else:            
                
            if target_func is not None:
                name=target_func[1]
            else:
                name=target_name
            
                    
            for begin ,items in malloc_pro.items(): 
                Addrs=self._analysis._mapAddrOfMallocInCallerAndCalle(name,caller,whole=True)
                for i in Addrs:
                    tmp_wr=self._analysis.trackWriteIntoARGCCINCallee(name,i)
                    if len(tmp_wr) > 0 :
                        tmp_res=(begin,name,tmp_wr)
                        wr_points.append(tmp_res)
                    
                    
    
        return wr_points
    
    
    def _getMallocPosOnArgs(self):
        malloc_args={}
        for addr,specs in self._maps.items():
            for func_name,props in specs:
                if func_name != 'main':
                    if 'rbp' not in props[0]:
                        if func_name not in malloc_args.keys():
                            malloc_args[func_name]={}
                            malloc_args[func_name][self._analysis.project.factory.cc().ARG_REGS.index(props[0])+1]=addr
                        else:
                            malloc_args[func_name][self._analysis.project.factory.cc().ARG_REGS.index(props[0])+1]=addr
        return malloc_args