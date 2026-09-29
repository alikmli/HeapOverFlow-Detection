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
            return
        #TODO : check free is called in callee function or in functions called

        wr_res=self._checkIsWriteInTargetFunction(caller,malloc_pro,target_name=caller)
        if len(wr_res) > 0 :
            print('write occurred in {0} function at {1} addresses. '.format(caller,wr_res[0][1]))
            unit_list.extend(wr_res)
            
            
        
        begin=caller_func.startpoint.addr
        end=self._analysis.getEndPoint(caller)
        funcs=self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(caller,begin,end))


        if len(funcs) > 0 :
            for func in funcs:
                call_chains=self._getCallChain(func[1])
                wr_res=self._checkIsWriteInTargetFunction(caller,malloc_pro,target_func=func)
                if len(wr_res) > 0 :
                    for tmp_res in wr_res:
                        if tmp_res not in unit_list:
                            print('write occurred in {0} function at {1} addresses.'.format(tmp_res[0],tmp_res[1]))
                            unit_list.append(tmp_res)
                
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
                        tmp_res=self._analysis.trackWriteIntoARGCCINCallee(callee,item) 
                        if len(tmp_res)>0:
                            res=(callee,tmp_res)
                            if res not in units:
                                print('write occurred in {0} function at {1} addresses.'.format(res[0],res[1]))
                                units.append(res)
            else:
                if caller in argc_hist.keys():
                    caller_argcc=argc_hist[caller]
                    callee_argc = self._analysis._mapRegccInCalleeAndCaller(caller,callee,caller_argcc)
                    for _,argc in callee_argc:
                        argc_hist[callee]=argc
                        for item in argc:
                            tmp_res=self._analysis.trackWriteIntoARGCCINCallee(callee,item)
                            if len(tmp_res) > 0 :
                                res=(callee,tmp_res)
                                if res not in units:
                                    print('write occurred in {0} function at {1} addresses.'.format(res[0],res[1]))
                                    units.append(res)
                                
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
        wr_points=[]
        if target_name is not None:
            if caller  == target_name:
                for addr ,argcc in malloc_pro.items(): 
                    tmp_wr=self._analysis.trackWriteIntoARGCCINCallee(caller,argcc)
                    if len(tmp_wr) > 0 :
                        #tmp_res=(target_name,tmp_wr,addr)
                        tmp_res=(target_name,tmp_wr)
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
                        tmp_res=(name,tmp_wr)
                        wr_points.append(tmp_res)
                    
                    
    
        return wr_points
        
    def _getCalleesForCaller(chain,caller):
        res=[]
        for cr,ce in chain:
            if cr == caller:
                res.append( ce)
        return res

    def _searchInMaps(self,addr,func_name):
        maplist=self._maps[addr]
        for item in maplist:
            if item[0] == func_name:
                return item[1]
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
        
