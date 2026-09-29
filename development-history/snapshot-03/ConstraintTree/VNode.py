#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Sep 11 23:39:17 2020

@author: ali
"""



class _VNode:
    def __init__(self,inode=None,block=None,constraints=None,parent_addr=None,satisfiable=False):
        if block is None:
            self.blocks=[]
        else:
            self.blocks=[block]
        
        if constraints is None:
            self.constraints=[]
        else:      
            self.constraints=constraints
        self.Term=[]
        self.V=[]
        self.v=[]
        self._called=[]
        self.inode=inode
        self._has_child=False
        self._parent_addr=parent_addr
        self._satisfiable=satisfiable
        self._vul_susp=False
        self._extra_vul_const=[]
        

    def addVulConstraint(self,constraint):
        self._extra_vul_const.append(constraint)
        
        
    def addSystemIn(self,V):
        self.V.append(V)
    
    def _addCallee(self,addr):
        self._called.append(addr)
        
    def addUnitIn(self,v):
        self.v.append(v)
        
    def checkForConst(self,con):
        for item in self.constraints:
            if con is item:
                return True
        return False
    
    def addConstraints(self,consts,parent):

                
        for item in consts:
            if self.checkForConst(item) == False:
                self.constraints.append(item)
                self.Term.append(item)
        
        for item in parent.constraints:
            if self.checkForConst(item) == False:
                self.constraints.append(item)

                
    def addBlock(self,addr):
        if addr not in self.blocks:
            self.blocks.append(addr)
        
    @classmethod
    def getNodeNumber(cls):
        return cls.inode
    
    def pp(self):
        content='Node-{0}\nConstraints: {1}\nUnitInputs: {2}\nSystemInputs: {3}\nBasicBlocks Addr: {4}\nCallees: {5}\n'.format(self.inode,self.constraints,self.v,self.V,self.blocks,self._called)
        print(content)
       
    def __str__(self):
        return 'Node-{0}'.format(self.inode)
        





