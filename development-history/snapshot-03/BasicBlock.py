

class Address:
    def __init__(self,addr=None,capstonInst=None,vex=None,next=None):
        self.addr=addr
        self.capstonInst=capstonInst
        self.vex=vex
        self.next=next
        
    def setAddr(self,addr):
        self.addr=addr
        
    def setCapstonInst(self,inst):
        self.capstonInst=inst
        
    def setVex(self,vex):
        self.vex=vex
        
    def pp(self):
        print('***** Assembly instructure ****')
        print(self.capstonInst)
        print('\n')
        print('***** Vex instructure *****')
        for i in self.vex:
            print(i)
        print('\n')
        
    
class BBHandler:
    addrList=list()
    def __init__(self,proj:angr.project.Project,state):
        self.head=self.tail=None
        self.proj=proj
        self.state=state
        self.baseArrayAddrRegs=None
        if self.state is not None:
            self.setValues()
        
    
    def changeState(self,state):
        if state is not None:
            self.state=state
            self.setValues()
    
                
    def setValues(self):
        for i in self.state.block().vex.statements: 
            if i.tag == 'Ist_IMark':
               node=Address(addr=i.addr)
               BBHandler.addrList.append(i.addr)
               node.vex=list() 
               b=self.proj.factory.block(i.addr)
               node.capstonInst=b.capstone.insns[0]
               if self.head is None:
                   self.head=self.tail=node
               else:
                   self.tail.next=node
                   self.tail=self.tail.next
            else:
                x=self.tail.vex
                x.append(i)   
                
    def pp(self):
        tmp=self.head
        while tmp is not None:
            print('in address: {0}\n+'.format(tmp.addr))
            print('capston : ')
            print(tmp.capstonInst)
            print('-'*40)
            print('vex translate : ')
            for i in tmp.vex:
                print(i)
            tmp=tmp.next
            print('\n')
                
            
    def getInstAtIndex(self,index)->Address:
        current = 0 ;
        tmp =self.head
        while tmp is not None:
            if current == index:
                return tmp
            else :
                tmp=tmp.next
                current +=1
                
                       
    def __len__(self):
        return self.state.block().instructions


    def getRegsName(self,offset):
        for  j in self.state.block().vex.arch.register_list: 
            if offset is j.vex_offset:
                 return j.name
             
                
    def getRegOffset(self,reg_name):
        for  j in self.state.block().vex.arch.register_list: 
            if j.name == reg_name:
                return j.vex_offset 
            
            
    
    def searchRegsByAddressInVex(self,addr):
        reg_name=None
        tmp=self.head
        while tmp is not None:
            for i in tmp.vex:
                if isinstance(i,pyvex.IRStmt.WrTmp) :
                     if isinstance(i.data,pyvex.IRExpr.Get):
                         reg_name=self.getRegsName(i.data.offset)
                         if addr == self.state.reg_concrete(reg_name):
                             return reg_name
            tmp=tmp.next
                                  
     
                
    def getVexListCommand(self,vexType):
        tmp=self.head
        result=list()
        while tmp is not None:
            for i in tmp.vex:
                if isinstance(i,vexType):
                    result.append(i)
            tmp=tmp.next
                    
        return result
    
    
    
    def isLoop(self):
        b=self.state.block()
        exits=list(b.vex.exit_statements)
        for i in exits:
            stmt=i[2]
            currentAddr=i[0]
            if stmt.jumpkind == 'Ijk_Boring':
                if currentAddr > stmt.dst.value:
                    return True
        
        return False
    
    
    
                
    def discoveringBufferOverFlow(self,bound):
        if len(bound) != 0:
            self.getBaseArrayAddrReg(bound[0])
            if self.isLoop() and (self.baseArrayAddrRegs is not None):
                value = self.reg_concrete(self.baseArrayAddrRegs)
                line=bound[0] + bound[1]
                if (value is not None) and (value >= bound[0]) and (value > line):
                    raise BaseException('Buffer Overflow')
                    
                    
    
            
        
    
    def getBaseArrayAddrReg(self,base):
        puts=self.getVexListCommand(pyvex.IRStmt.Put) 
        offsets=set()
        for i in puts:
            offsets.add(i.offset)
           
        regs=list()
        for i in offsets:
            regs.append(self.getRegsName(i))
        
        for i in regs:
            value=self.reg_concrete(i)
            
            
            if value is None:
                continue
            if value == base:
                   name=i
                   if name[len(i) -1 ] == 'i':
                       name.replace('i','x')
                   self.baseArrayAddrRegs=i
                   return
               
               
    def reg_concrete(self, *args, **kwargs):
        """
        Returns the contents of a register but, if that register is symbolic,
        raises a SimValueError.
        """
        e = self.state.registers.load(*args, **kwargs)
        if self.state.solver.symbolic(e):
            return None
        return self.state.solver.eval(e)
                 

        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        

        
        
        
        