#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jul 13 16:59:10 2020

@author: ali
"""


class Units:
    
    def __init__(self,valAnalysis):
        self._analysis=valAnalysis
        
        
    def getUnitForHeapBufferOverFlow(self):
        result=[]
        for addr , func in self._analysis.getCaller('malloc'):
            begin=func.startpoint.addr
            end=self._analysis.getEndPoint(func.name)
            funcs=self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(func.name,begin,end))
            for f_addr,f_name in funcs:
                for callblock in self._analysis.getBlockOFFuctionCall(f_name,func.name):
                    result.extend(self._getUnitsForOnBlocks(func.name,callblock))
                
        return result
    
    
    def _getUnitsForOnBlocks(self,caller,callblock=None):
        #getting malloc addresses
        caller_func=self._analysis.resolveAddrByFunction(self._analysis.getFuncAddress(caller))
        unit_list=list()
        malloc_pro=dict()
        funcs_malloc=self._analysis.getAddressOfFunctionCall('malloc')
        for i in self._analysis.getRetStoreLocOnStackOfFunction('malloc',caller):
            for addr,value in i.items():
                for item in funcs_malloc:
                    if item[0] == addr and item[1].name == caller:
                        if callblock is None:
                             malloc_pro[addr]=value
                             break
                        elif self._isValidAddress(callblock,caller,value):
                            malloc_pro[addr]=value
                            break
        
        for addr,argc in malloc_pro.items():
            tmp_res=self._checkForStrcpy(caller,argc)
            if tmp_res is not None and len(tmp_res)>0:
                unit_list.append((addr,caller,tmp_res))
            
        if len(malloc_pro) ==0 : 
            return
        #TODO : check free is called in callee function or in functions called
        wr_res=self._checkIsWriteInTargetFunction(caller,malloc_pro,target_name=caller)
        if len(wr_res) > 0 :       
            unit_list.extend(wr_res)

        begin=caller_func.startpoint.addr
        end=self._analysis.getEndPoint(caller)
        funcs=self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(caller,begin,end))

        if len(funcs) > 0 :
            for func in funcs:
                maps={}
                for addr,argcc in malloc_pro.items():
                    maps[addr]=[(caller,argcc)]
                    
                call_chains=self._getCallChain(func[1])
                argcc=self._analysis._mapAddrOfMallocInCallerAndCalle(func[1],caller,whole=True)
                key_maps=self._analysis._mapAddrOfMallocInCallerAndCalle(func[1],caller)
                for addr,argc in self.searchInMaps(caller,maps):
                    key=argc[1].con.value
                    value=key_maps[key]
                    for argc in argcc:
                        if argc[1].con.value==value:
                            maps[addr].append((func[1],argc))
                            break
        
                for chain in call_chains:
                    chain_caller,chain_callee=chain
                    for addr,argc in self.searchInMaps(chain_caller,maps):
                        res=self._analysis._mapRegccInCalleeAndCaller(chain_caller,chain_callee,[argc])[0][1]
                        if res is not None :
                            maps[addr].append((chain_callee,res[0]))
                
                for addr,items in maps.items():
                    for func_name,argcc in items:
                        if func_name == caller:continue
                        res=self._analysis.trackWriteIntoARGCCINCallee(func_name,argcc)
                        tmp_res=self._checkForStrcpy(func_name,argcc)
                        if tmp_res is not None and len(tmp_res)>0:
                            unit_list.append((addr,func_name,tmp_res))
                        if len(res)>0:
                            unit_list.append((addr,func_name,res))


        return unit_list
    
    def _checkForStrcpy(self,caller,argcaller):
        strcpy_callblocks=self._analysis.getBlockOFFuctionCall('strcpy',caller)
        if strcpy_callblocks is None:
            return 
        
        result=[]
        dst_strcpy=self._analysis.project.factory.cc().ARG_REGS[0]
        for callblock in strcpy_callblocks:
            for argc in self._analysis.getArgsCC(callblock.vex,self._analysis.getFuncAddress('strcpy')):
                if argc[1].con.value == argcaller[1].con.value and argc[0] == dst_strcpy:
                    result.append(('strcpy',callblock.instruction_addrs[-1],'dst') )
                if argc[1].con.value == argcaller[1].con.value and argc[0] == src_strcpy:
                    result.append(('strcpy',callblock.instruction_addrs[-1],'src') )
        return result
                    
            
    def _isValidAddress(self,callback,caller,value):
        callee=None
        if callback.vex.jumpkind == 'Ijk_Call':
            callee_addr=callback.vex.constant_jump_targets.copy().pop()
            callee=self._analysis.resolveAddrByFunction(callee_addr).name
        if callee is None:
            raise ValueError('Not Valid Callback')
        
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
                result.append((caller,func[1]))
                uncheckedList.append(func[1])
            
            if len(uncheckedList) == 0:
                break
            caller=uncheckedList.pop()
             
      
        return result
    
    
    def searchInMaps(self,target_name,maps):
        res=[]
        for addr,items in maps.items():
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