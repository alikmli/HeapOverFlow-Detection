

import angr ,claripy
import numpy as np

class SimExtractParams(angr.SimProcedure):
    '''
    usage
    pointers={1:'intPointer',2:'floatPointer',3:'int',4:'char',5:'float'}
    mycc=proj.factory.cc_from_arg_kinds(fp_args=[False,False,False,False,True])
    proj.hook_symbol('sum',sumSim(cc=mycc,pointers=pointers,num_args=len(pointers))) 
    '''
    def run(self, *args, pointers=None):
        self.state.globals['args']=[]
        for numb,typ in pointers.items():
            argRes=None
            if typ == 'intPointer':
                addr=args[numb-1].ast.args[0]
                argRes=int(np.int32(self.state.mem[addr].long.concrete))
            elif typ == 'charPointer':
                addr=args[numb-1].ast.args[0]
                argRes=chr(self.state.mem[addr].long.concrete)
            elif typ == 'floatPointer':
                addr=args[numb-1].ast.args[0]
                value=self.state.mem[addr].long.concrete
                tmp_val=claripy.BVV(value,32)
                argRes=tmp_val.raw_to_fp().args[0]
            elif typ == 'doublePointer':
                addr=args[numb-1].ast.args[0] 
                value=self.state.mem[addr].long.concrete 
                tmp_val=claripy.BVV(value,64)
                fp=tmp_val.raw_to_fp()
                argRes=tmp_val.raw_to_fp().args[0]
            elif typ in 'char':
                argRes=chr(args[numb-1].ast.args[0])
            elif typ in 'int':
                val=args[numb-1].ast
                argRes=int(np.int32(self.state.solver.eval(val)))
            elif typ in 'float':
                tmp_val=claripy.BVV(args[numb-1].args[0],32)
                argRes=tmp_val.raw_to_fp().args[0]
            else:
                tmp_val=claripy.BVV(args[numb-1].args[0],64)
                argRes=tmp_val.raw_to_fp().args[0]
            self.state.globals['args'].append(argRes)
        self.exit(1)    
        return 0
            