#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jul 26 20:24:03 2020

@author: ali
"""
    
    




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


    
            
            
            