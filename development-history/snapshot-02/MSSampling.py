
import numpy as np
import os
class MCSimulation:
    def __init__(self,config_path):
        self._path=config_path
        self._numbs=0
        self._types=[]
        self._distros=[]
        with open(self._path,'r') as handler:
            lines=handler.readlines()
        
            pointer=0
            for line in lines:
                if line.startswith('#') or line.startswith('\n'):continue
                tmp=line.replace('\n','')
                if pointer==0:
                    self._numbs=int(tmp)
                    pointer+=1
                elif pointer ==1:
                    self._types=tmp.split(',')
                    pointer+=1
                elif pointer ==2:
                    self._distros.append(tmp.split(','))
            


    def getGaussianSample(self,indx):
        dist=self._distros[indx]
        mean=int(dist[1].strip())
        dev=int(dist[2].strip())
        return str(int(np.random.normal(loc=mean,scale=dev)))
    
    
    def generate(self):
        lines=[]    
        for i in range(0,self._numbs):
            line=[]
            pointer=0
            for tp in self._types:
                if tp.strip() == 'int':
                    dist=self._distros[pointer]
                    if dist[0].strip() == 'normal':
                        line.append(str(int(np.random.normal(loc=int(dist[1].strip()),scale=int(dist[2].strip())))))
                        pointer+=1

                
                
            lines.append(line)
        new_path=os.path.split(self._path)[0] + '/MCgenerated.txt';
        with open(new_path,'w+') as handler:
            for line in lines:
                handler.write(','.join(line) + '\n')
        
            
        return lines

if __name__ == '__main__':
    import angr,claripy,pyvex,monkeyhex
    proj=angr.Project('total',load_options={'auto_load_libs':False})

    x=MCSimulation('/home/ali/tmp/mc.cfg')
    inputs=x.generate()
    results=[]
    for varrs in inputs:
        x=claripy.BVV(str(varrs[0]))
        y=claripy.BVV(str(varrs[1]))
        
        simfile=angr.SimFileStream('/dev/stdin',content=x.concat(y))
        entry=proj.factory.entry_state(stdin=simfile)
        simgr=proj.factory.simulation_manager(entry)
        
        simgr.run()
        result='bad'
        if len(simgr.deadended) == 1:
            if b'Go away' in simgr.deadended[0].posix.stdout.concretize():
                result='normal'
            if  b'your lucky' in simgr.deadended[0].posix.stdout.concretize():
                result='good'
        
        varrs.append(result)
        results.append(varrs)
   
    with open('./data.data','w+') as handler:
        for line in results:
            handler.write(','.join(line) + '\n')
        
    
    
        
    
    
    
    
    
    
    
    
    
    
    
    