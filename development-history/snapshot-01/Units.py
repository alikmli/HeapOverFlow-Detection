#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jul 13 16:59:10 2020

@author: ali
"""


class Units:
    
    def __init__(self,valAnalysis):
        self._analysis=valAnalysis
        
        
    def getUnitForHeapBufferOverFlow(self,caller,level=1):
        
        #getting malloc addresses
        caller_func=self._analysis.resolveAddrByFunction(self._analysis.getFuncAddress(caller))
        unit_list=list()
        malloc_pro=dict()
        funcs_malloc=self._analysis.getAddressOfFunctionCall('malloc')
        for i in self._analysis.getRetStoreLocOnStackOfFunction('malloc',caller):
            for addr,value in i.items():
                for item in funcs_malloc:
                    if item[0] == addr and item[1].name == caller:
                        malloc_pro[addr]=value
                        break
        
        
        if len(malloc_pro) ==0 : 
            print('there is no malloc call in this caller ')
            return
        #TODO : check free is called in callee function or in functions called

        if self._checkIsWriteInTargetFunction(caller,malloc_pro,target_name=caller):
            unit_list.append(caller)
            
            
        
        begin=caller_func.startpoint.addr
        end=self._analysis.getEndPoint(caller)
        funcs=self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(caller,begin,end))


        if len(funcs) > 0 :
            for func in funcs:
                call_chains=self._getCallChain(func[1])
                if self._checkIsWriteInTargetFunction(caller,malloc_pro,target_func=func):
                    unit_list.append(func[1])
                    
                argcc=self._analysis._mapAddrOfMallocInCallerAndCalle(func[1],caller,whole=True) 
                unit_list.extend(self._chainUnits(func[1],call_chains,argcc))
        
        
        return unit_list
        
    def _chainUnits(self,caller_name,chain,argcc):
        units=[]
        argc_hist=dict()

        for caller,callee in chain:
            if caller == caller_name:
                callee_argc = self._analysis._mapRegccInCalleeAndCaller(caller,callee,argcc)
                for _,argc in callee_argc:
                    argc_hist[callee]=argc
                    for item in argc:
                        if len(self._analysis.trackWriteIntoARGCCINCallee(callee,item)) > 0 :
                            if callee not in units:
                                units.append(callee)
            else:
                if caller in argc_hist.keys():
                    caller_argcc=argc_hist[caller]
                    callee_argc = self._analysis._mapRegccInCalleeAndCaller(caller,callee,caller_argcc)
                    for _,argc in callee_argc:
                        argc_hist[callee]=argc
                        for item in argc:
                            if len(self._analysis.trackWriteIntoARGCCINCallee(callee,item)) > 0 :
                                if callee not in units:
                                    units.append(callee)
                                
        del(argc_hist)
        return units
                
        
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
        
    def _checkIsWriteInTargetFunction(self,caller,malloc_pro,target_name=None,target_func=None):
        
        if target_name is not None:
            if caller  == target_name:
                for addr ,argcc in malloc_pro.items(): 
                    if len(self._analysis.trackWriteIntoARGCCINCallee(caller,argcc)) > 0 :
                        return True
                return False
                    
                
        if target_func is not None:
            name=target_func[1]
        else:
            name=target_name
        
                
        for begin ,items in malloc_pro.items(): 
            Addrs=self._analysis._mapAddrOfMallocInCallerAndCalle(name,caller,whole=True)
            for i in Addrs:
                rs=self._analysis.trackWriteIntoARGCCINCallee(name,i)
                if len(rs) > 0 :
                    print('yeap there is a write','{0}(rbp,{1})'.format(i[2],hex(i[1].con.value)))
                    return True
                    
                    
    
        return False
        
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
        