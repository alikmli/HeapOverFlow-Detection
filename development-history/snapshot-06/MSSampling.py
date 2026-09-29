import numpy as np
from random import uniform
from enum import Enum
from covertable import make, sorters, criteria
import random


class MCSimulation:
    _nFactorSec = Enum('Sections', [('HOW_MANY', 1), ('TYPES', 2),('ARRAYS',3),('NPAIRS', 5),('GROUPS',6)])
    _simpleSec = Enum('Sections', [('HOW_MANY', 1), ('TYPES', 2),('ARRAYS',3),('DISTROS', 4)])
    _wholeSecs = Enum('Sections', [('HOW_MANY', 1), ('TYPES', 2),('ARRAYS',3),('DISTROS', 4),('NPAIRS', 5),('GROUPS',6)])
    INT_MAX=2**32-1
    FLOAT_MAX=2**63-1
    #TODO add types are entered in file are valid based of their type name
    def __init__(self,config_file,nfactor=False):
        self._nfactor=nfactor
        self.active_section= MCSimulation._nFactorSec if nfactor else MCSimulation._simpleSec
        self._types=[]
        self._distros={}
        self._numbs=0
        self._npair=0
        self._groups={}
        self.active_part=None
        with open(config_file,'r+') as handler:
            lines=handler.readlines()
            for line in lines :
                if line.startswith('#') or line.startswith('\n'):continue
                else:
                    line=line.strip()
                    if line.upper() in self.active_section.__members__.keys() :
                        self.active_part=self.active_section.__members__.get(line.upper())
                        continue
                    elif line.upper() in MCSimulation._wholeSecs.__members__.keys():
                        self.active_part=None
                        continue
                    if self.active_part is not None:
                        if self.active_part.name is MCSimulation._wholeSecs.HOW_MANY.name:
                            self._numbs=int(line)
                        elif self.active_part.name is MCSimulation._wholeSecs.TYPES.name:
                            self._types=[tp.strip() for tp in line.split(',')]
                        elif self.active_part.name is MCSimulation._wholeSecs.ARRAYS.name:
                            tmp_res=line.split(',')
                            for indx in range(len(tmp_res)):
                                tmp_res[indx]=tmp_res[indx].replace(' ','')
                            self._types.insert(int(tmp_res[0])-1,tuple(tmp_res[1:]))
                        elif self.active_part.name is MCSimulation._wholeSecs.DISTROS.name:
                            tmp_res=[dist.strip() for dist in line.split(',')]
                            key=int(tmp_res[0])-1
                            value=tmp_res[1:]
                            self._distros[key]=value
                        elif self.active_part.name is MCSimulation._wholeSecs.NPAIRS.name:
                            self._npair=int(line)
                        elif self.active_part.name is MCSimulation._wholeSecs.GROUPS.name:
                            param,groups=line.split(':')
                            idx=1
                            self._groups[param]={}
                            for gp in groups.split(','):
                                gp_name='{0}{1}_g{2}'.format(param[0],param[-1],idx)
                                self._groups[param][gp_name]=gp.strip()
                                idx=idx+1
                        
                    
    def _getSign32BitRandomInt(self):
        return random.randint(-2147483648,2147483647) 
    def _getUnSign32BitRandomInt(self):
        return random.randint(0,4294967295) 
    
    def getCharStarSample(self,size):
        st=[]
        for i in range(int(size)-2):
            st.append(chr(int(uniform(33,126))))
        st.append('\x00')
        return ''.join(st)
    
    def getGaussianSample(self,indx,tp=None):
        if tp is not None:
            if 'char' == tp:
                return chr(int(uniform(33,126)))
            elif 'int' in  tp:
                if 'unsigned' in tp:
                    return self._getUnSign32BitRandomInt()
                else:
                    return self._getSign32BitRandomInt()
                
        return self._generateBaseOnType(indx)

    
    def getVarTypes(self,index):
        tp=self._types[index]
        return tp.strip() if isinstance(tp,str) else tp

    
    def _generateBaseOnType(self,indx):
        tp=self._types[indx]
        if isinstance(tp,tuple):
            _tp,_count=tp
            if 'char' in _tp and '*' in _tp:
                st=[]
                for i in range(int(_count)-1):
                    st.append(chr(int(uniform(33,126))))
                st.append('\x00')
                return ''.join(st)

        elif tp.strip() == 'char':
            return int(uniform(33,126))
        else:
            dist=self._distros.get(indx)
            if tp.strip() == 'int' or  tp.strip() == 'short':
                if dist[0].strip() == 'normal':
                    return str(int(np.random.normal(loc=int(dist[1].strip()),scale=int(dist[2].strip()))))
                
            elif tp.strip() == 'float' or tp.strip() == 'double':
                if dist[0].strip() == 'normal':
                    return str(round(np.random.normal(loc=float(dist[1].strip()),scale=float(dist[2].strip())),2))
    
            elif tp.strip() == 'unsigned int':
                if dist[0].strip() == 'normal':
                    mean=int(dist[1].strip())
                    dev=int(dist[2].strip())
                    if mean - dev < 0 :
                        raise ValueError('incorrect bound for unsigned type .')
                    
                    value=int(np.random.normal(loc=int(dist[1].strip()),scale=int(dist[2].strip())))
                    while value < 0 :
                        value=int(np.random.normal(loc=int(dist[1].strip()),scale=int(dist[2].strip())))
                    return str(value)



    def _mapTypeToVarIndex(self,tp):
        res = []
        for indx in range(len(self._types)):
            if isinstance(self._types[indx],tuple):
                if self._types[indx][0].lower() == tp.lower():
                    res.append(indx)
            elif self._types[indx].lower()  == tp.lower():
                res.append(indx)
                
        return res
    
    def generate(self,count=None):
        lines=[]   
        length=0
        if (count is not None) and (count > 0):
            length=count
        else:
            length=self._numbs
        for i in range(0,length):
            line=[]
            for indx in range(len(self._types)):
                line.append(self._generateBaseOnType(indx))
            lines.append(line)
            
            
        return lines
    
    
    def _generateNFactor(self):
        params=[]
        for name,item in self._groups.items():
            params.append(list(item.keys()))
        res=make(
             params,  # list factors
             length=self._npair,  # default: 2
             sorter=sorters.random,  # default: sorters.hash
             criterion=criteria.greedy,  # default: criteria.greedy
             seed=100,  # default: 
             post_filter=self._nFactorHandelTypes
            )
        return res
    
    def _nFactorHandelTypes(self,row):
        
        for idx in range(len(row)):
            key='param_{}'.format(idx +1)
            tp=self._types[idx]
            bound=self._groups[key][row[idx]]
            if isinstance(tp,tuple):
                row[idx]=self._handelCharStar(bound)
            elif 'int' in tp.lower():
                row[idx]=self._handelNameric(bound,MCSimulation.INT_MAX)
            elif 'float' in tp.lower():
                row[idx]=self._handelNameric(bound,MCSimulation.FLOAT_MAX,isfloat=True)
            elif 'char' in tp.lower():
                row[idx]=self._handelChar(bound)

        return True 
    
    def _handelCharStar(self,bound):
        if '-' in bound:
            ch=bound[1:len(bound)-1].split('-')
            return random.choice(ch)
        else:
            raise  ValueError('bound is not valid ...!!')
            
    def _handelChar(self,bound):
        if ';' in bound:
            min_value=self._getLowerBound(bound,128,ischar=True)
            max_value=self._getUpperBound(bound,128,ischar=True)
            if min_value < max_value:
                return chr(random.randint(min_value,max_value))
            else:
                raise  ValueError('bound is not valid ...!!')
        elif '-' in bound:
            ch=bound[1:len(bound)-1].split('-')
            return random.choice(ch)
        else:
            raise ValueError('bound is not valid...!!')
            
    
    def _handelNameric(self,bound,maxsize,isfloat=False):
        bound=bound.strip()
        min_value=self._getLowerBound(bound,maxsize,isfloat)
        max_value=self._getUpperBound(bound,maxsize,isfloat)
    
        if min_value < max_value:
            if isfloat:
                return random.uniform(min_value,max_value)
            return random.randint(min_value,max_value)
        else:
            raise  ValueError('bound is not valid ...!!')
        
    
    def _getUpperBound(self,bound,maxsize,isfloat=False,ischar=False):
        if bound.endswith(']') :
            lower=bound.replace(']','',1).split(';')[1]
            if ischar:
                max_value=ord(lower)
            elif isfloat:
                max_value=float(lower)
            else:
                max_value=int(lower)
        elif bound.endswith(')') :
            lower=(bound.replace(')','',1).split(';')[1].strip())
            if '-' is not lower:
                if ischar:
                    max_value=ord(lower)-1
                elif isfloat:
                    max_value=float(lower)- 0.0001
                else:
                    max_value=int(lower)-1
            else:
                if ischar:
                    raise ValueError('bound is not valid for char...!!')  
                max_value=maxsize
        else:
            raise ValueError('bound is not valid...!!')
        
        return max_value
    
    def _getLowerBound(self,bound,maxsize,isfloat=False,ischar=False):
        if bound.startswith('[') :
            lower=bound.replace('[','',1).split(';')[0]
            if ischar:
                min_value=ord(lower)
            elif isfloat:
                min_value=float(lower)
            else:
                min_value=int(lower)
        elif bound.startswith('(') :
            lower=(bound.replace('(','',1).split(';')[0].strip())
            if '-' is not lower:
                if ischar:
                    min_value=ord(lower)
                if isfloat:
                    min_value=float(lower) - 0.0001
                else:
                    min_value=int(lower) + 1
            else:
                if ischar:
                    raise ValueError('bound is not valid for char...!!')  
                min_value=-maxsize-1
        else:
            raise ValueError('bound is not valid...!!')
        return min_value
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    