#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 22 11:42:35 2020

@author: ali
"""
from analysis.MCSimulation import MCSimulation
from analysis.SimExtractIntPointerParams import SimExtractIntPointerParams
from analysis.Tar3 import runTAR3,_correctInputs,_seperateValues
import angr,claripy,networkx as nx
from numpy import array
from numpy import polyfit
from numpy import poly1d
from scipy.interpolate import CubicSpline
import os,glob
from analysis.Tar3Ranges import  Range
from random import randrange

class Cover:
    
    def __init__(self,project,CFGAnalysis,TreeAnalysis,target_func,*args):
        self.project=project
        self.analysis = CFGAnalysis
        self.target_func = target_func
        self.tree=TreeAnalysis
        self.tree.generateForCallable(self.target_func, *args)
        self._uncoverNodes={}
        
        
    def _extractUnitV(self,*args):
        sign=lambda x:  '+{}'.format(x) if (x>0) else '{}'.format(x)
        self.project.hook_symbol(self.target_func.name,SimExtractIntPointerParams())
        sys_V=[]
        for var in args:
            sys_V.append(claripy.BVV(bytes(sign(var),encoding='utf-8')))
        bytes_ast = claripy.Concat(*sys_V)
        simfile=angr.SimFileStream('/dev/stdin',content=bytes_ast)
        state=self.project.factory.entry_state(stdin=simfile)
        simgr=self.project.factory.simulation_manager(state)
        simgr.run()
        #u must complete this for casees like  all sys vars does not pass to unit
        return simgr.deadended[0].globals
    
    def cover(self,config_filename,n=1,pointer_indexes=None):
        mc=MCSimulation(config_filename)
        self._generatingVitness(mc,pointer_indexes)
        root=list(self.tree._graph.nodes)[0]
        I=self._copy(root.V)
        for node in nx.bfs_tree(self.tree._graph,source=root):
            if node is not root:
                parent=self.tree._parent(node)
                siblings=self.tree._successors(parent=parent,depth_limit=1)                
                if self._covered(siblings):
                    VV=self._copy(node.V)
                    VVV=[]
                    V=self._copy(I)
                    for item in V:
                        if item not in VV:
                            VVV.append(item.copy())
                    runTAR3(I,V,VV,VVV,'cov-'+str(node.inode))
                    
                elif node._satisfiable and len(node.v) == 0:
                    V=self._copy(I)
                    v=self._copy(root.v)
                    self.computeMap(node.Term,I,V,v,node,parent)
        #build new test case 
        result=self._generateInputs(mc,n)
                
        return result
    
    def _generateInputs(self,mc,n):
        result={}
        for node_index in self._uncoverNodes.keys():
            target_node=self.tree.getNodeByIndex(node_index)
            result[node_index]=[]
            ranges=self._generatingConsistantBoundThrowOnePath(target_node)
            solver=claripy.Solver()
            solver.add(target_node.constraints)
            if len(ranges) == 0:
                svar=[]
                except_var=[]
                for var in self.tree._allvars:
                    var_name=list(var.variables)[0]
                    if var_name in solver.variables:
                        svar.append(var)
                    else:
                        except_var.append(var_name)
                for gen in solver.batch_eval(svar,n,exact=True):
                    generated=list(gen)
                    generated.reverse()
                    tmp_res=[]
                    for var in self.tree._allvars:
                        var_name=list(var.variables)[0]
                        if var_name in except_var:
                            index=int(var_name.split('_')[1]) -1
                            tmp_res.append(int(mc.getGaussianSample(index)))
                        else:
                            if var_name in self._uncoverNodes.get(node_index).keys():
                                func=self._uncoverNodes.get(node_index).get(var_name)[2]
                                tmp_res.append(int(func(generated.pop())))
                            else:
                                tmp_res.append(generated.pop())
                    result.get(node_index).append(tuple(tmp_res))
            else:
                svar=[]
                except_var=[]
                for var in self.tree._allvars:
                    var_name=list(var.variables)[0]
                    if var_name in self._uncoverNodes.get(node_index).keys():
                        svar.append(var)
                    else:
                        except_var.append(var_name)
                tmp_eval_res={}
                for var in svar:
                    var_name=list(var.variables)[0]
                    if var_name in solver.variables:
                        tmp_eval_res[var_name]=solver.eval(var,n,exact=True)
                    else:
                        tmp_eval_res[var_name]=self._generateInBoundvalues(mc,var_name,ranges,n)
                
                for i in range(n):
                    tmp_res=[]
                    for var in self.tree._allvars:
                        var_name=list(var.variables)[0]
                        if var_name not in except_var:
                            func=self._uncoverNodes.get(node_index).get(var_name)[2]
                            tmp_res.append(func(tmp_eval_res.get(var_name)[i]))
                        else:
                            tmp_res.append(self._generateInBoundvalues(mc,var_name,ranges,1)[0])
                    result.get(node_index).append(tuple(tmp_res))      
            
        return result
    
    def _generateInBoundvalues(self,mc,var_name,bounds,n):
        min_bnd=None
        max_bnd=None
        not_inbound=True
        result=[]
        for i in range(n):
            for b in bounds:
                if var_name in b.var_names:
                    not_inbound=False
                    if min_bnd is None :
                        min_bnd=float(b.bound.get(var_name)[0])
                        max_bnd=float(b.bound.get(var_name)[1])
                    else:
                        tmp_min=float(b.bound.get(var_name)[0])
                        tmp_max=float(b.bound.get(var_name)[1])
                        minb=min_bnd,maxb=max_bnd
                        if tmp_max > max_bnd and tmp_min >= max_bnd:
                            maxb=tmp_max
                        elif tmp_max <= min_bnd and tmp_min < min_bnd :
                            minb=tmp_min
                        else:
                            if tmp_max < max_bnd : 
                                maxb=tmp_max
                            if tmp_min > min_bnd :
                                minb = tmp_min
                        min_bnd,max_bnd=minb,maxb
            
            
            if not_inbound :
                indx=int(var_name.split('_')[1]) - 1
                result.append(mc.getGaussianSample(indx))
            
            min_bnd=int(min_bnd)
            max_bnd=int(max_bnd)
            if min_bnd  == max_bnd :
                result.append( min_bnd)
            else:
                result.append(randrange(min_bnd,max_bnd))
        
    
    
    
    def  computeMap(self,C,I,V,v,n,parent_n):
        i_n=set()
        for term in C:
            for var in term.variables:
                i_n.add(var)
                
        cons=[]
        for c in n.constraints:
            for var in i_n:
                if var in c.variables:
                    cons.append(c)
                    break
        
        _VV,_v=self._getClosetSet(cons,V,v)
        
        _VVV=[]
        _V=self._copy(V)
        for item in _V:
            if item not in _VV:
                _VVV.append(item.copy())
        
        smooth=runTAR3(I,_V,_VV,_VVV,'uncov-'+str(n.inode),smooth=True,vv=_v)
        print(smooth)

        if n.inode not in self._uncoverNodes.keys():
            self._uncoverNodes[n.inode]=dict()
            
            
        if len(self._uncoverNodes.get(n.inode)) == 0:
            for var_name,sys_in,uni_in in smooth:
                row=self._uncoverNodes.get(n.inode)
                if sys_in is not None:
                    f_n = CubicSpline(sys_in,uni_in) 
                    row[var_name]=[sys_in,uni_in,f_n]
                else:
                    row[var_name]=[]
        else:
            row=self._uncoverNodes.get(n.inode)
            for var_name,sys_in,uni_in in smooth:
                if len(row.get(var_name)) == 0 :
                    if sys_in is not None:
                        f_n = CubicSpline(sys_in,uni_in) 
                        row[var_name]=[sys_in,uni_in,f_n]
        
        if self._isSmooth(self._uncoverNodes.get(n.inode)) == False:
            for file in glob.glob('./.node-uncov-*'):
                os.remove(file)
            if parent_n is not None:
                print('in part 2')
                CC=[]
                CC.extend(C)
                CC.extend(parent_n.Term)
                pparent=None
                if parent_n.inode > 0:
                    pparent=self.tree._parent(parent_n)
                self.computeMap(CC,I,V,v,n,pparent)
            else:
                print('in part 3')
                pparent=n
                CC=[]
                CC.extend(pparent.Term)
                while pparent.inode > 0:
                    pparent=self.tree._parent(pparent)
                    CC.extend(pparent.Term)
                    if len(pparent.V) > 5:
                        break
                _VV=self._copy(pparent.V)
                _VVV=[]
                _V=self._copy(I)
                for item in _V:
                    if item not in _VV:
                        _VVV.append(item.copy())
                
                runTAR3(I,_V,_VV,_VVV,'uncov-'+str(n.inode))
                content=[]
                with open('./.node-uncov-'+str(n.inode)+'.txt','r') as handler:
                    content=handler.readlines()
                
                sys_v,unit_v=None,None
                if 'R' in content or 'No CDF.' in content or 'No Value' in content:
                    sys_v=array(self._copy(pparent.V))
                    unit_v=array(self._copy(pparent.v))
                else:
                    boundries=_seperateValues(content.copy())
                    sys_v,unit_v=_correctInputs(boundries,self._copy(pparent.V),self._copy(pparent.v))
                
                row=self._uncoverNodes.get(n.inode)
                for var_name,prop in row.items():
                    if len(prop) == 0:
                        idx=int(var_name.split('_')[1]) -1 
                        sys_v=array(sys_v)
                        unit_v=array(unit_v)
                        xdata=sys_v[:,idx]
                        ydata=unit_v[:,idx]
                        coeff=polyfit(xdata,ydata,1)
                        poly=poly1d(coeff)
                        prop.extend([xdata,ydata,poly])
                        
        for file in glob.glob('./.node-uncov-*'):
            os.remove(file)
                            
                        
    def _generatingConsistantBoundThrowOnePath(self,target_node):

        file='./.node-cov-{}.txt'
        target_node=self.tree._parent(target_node)
        bounds=[]
        while target_node.inode > 0:
            if os.path.exists(file.format(target_node.inode)):
                res=None
                with open(file.format(target_node.inode),'r') as handler:
                    res=handler.readlines()
          
                if ('R' in res) or ('No Value' in res) or ('No CDF.' in res):
                    target_node=self.tree._parent(target_node)
                    continue
                else:
                   vals=_seperateValues(res)
                   if len(bounds) == 0 :
                       for i in vals:
                           r=Range()
                           r.addRange(i)
                           bounds.append(r)
                   else:
                       for val in vals:
                           names=[]
                           for item in val:
                               names.append(item[0])
                           flag=True
                           for item in bounds:
                               if item.isMatch(names):
                                   item.correctBounds(val)
                                   flag=False
                           if flag :
                               r=Range()
                               r.addRange(val)
                               bounds.append(r)
                            
            target_node=self.tree._parent(target_node)           
        
        return bounds
    
    def _isSmooth(self,node_prop):
        for item in node_prop.values():
            if len(item)==0:
                return False
        return True
        
    
    def _copy(self,items):
        res=[]
        for item in items:
            res.append(item.copy())
            
        return res
    
    def _getOpr(self,cons):
        tmp_opr=[]
        for i in cons.children_asts():
            if ('Extract' in i.op) or ('BVV' in i.op) or ('BVS' in i.op) or ('Concat' in i.op):
                continue
            tmp_opr.append(i)
        return tmp_opr.pop() 
    
    def _getClosetSet(self,cons,system_v,unit_v):
        number_elements=int((len(system_v)*20)/100)
        _V=[None]*number_elements
        _v=[None]*number_elements
        weights=[None]*number_elements    
        for i in range(len(system_v)):
            inp=system_v[i]
            num_sat=0
            num_unsat=0
            for c in cons:
                s=claripy.Solver()
                s.add(c)
                var=list(c.variables)
                idx=[]
                if len(var) >1 :
                    for tmp_var in var:
                        idx.append(int(tmp_var.split('_')[1]))
                    idx.sort()
                    ivar=self._getOpr(c)
                    if 'add' in ivar.op:
                        total=0
                        for i in idx:
                            total= total + (inp[i-1])
                        if s.solution(ivar,total) : 
                            num_sat = num_sat + 1 
                        else:
                            num_unsat = num_unsat +1
                    elif 'sub' in ivar.op:
                        sub=inp[idx[0]-1]
                        for i in range(1,len(idx)):
                           sub = sub - (inp[idx[i]-1])
                        if s.solution(ivar,sub) : 
                           num_sat = num_sat + 1
                        else:
                           num_unsat = num_unsat +1
                else:
                    idx=int(var[0].split('_')[1])
                    variable=None
                    for v in self.tree._allvars:
                        if var[0] in list(v.variables):
                            variable=v 
                    if s.solution(variable,inp[idx-1]) :
                        num_sat = num_sat + 1
                    else:
                        num_unsat= num_unsat +1
            
            percent=int((num_sat/(num_sat+num_unsat))*100)
            if None in _V:
                index=_V.index(None)
                weights[index]=percent
                _V[index]=inp.copy()
                _v[index]=unit_v[i].copy()
            else:
                index=weights.index(min(weights))
                weights[index]=percent
                _V[index]=inp.copy()
                _v[index]=unit_v[i].copy()
                        

        return (_V,_v)
    
    def _covered(self,siblings):
        for node in siblings:
            if len(node.v) == 0:
                return False
        return True
    
    
    #V -> W
    
    def _generatingVitness(self,mc,pointer_indexes=None):
        inputs=mc.generate()
        sys_V=[]
        for var in inputs:
            sys_V=list(map(int,var))
            unit_v=self._extractUnitV(*sys_V)
            self._callUnit(unit_v,pointer_indexes,sys_V)
            
    

    def _callUnit(self,unit_v,pointers_indexes,sys_V):
        var=[]
        for i in range(0,len(unit_v)):
            if i in pointers_indexes:
                var.append(self.project.factory.callable.PointerWrapper(unit_v[i]))
            else:
                var.append(unit_v[i])
                
        
        self.project.unhook_symbol(self.target_func.name)
        call_obj=self.project.factory.callable(self.target_func.addr,concrete_only=True) 
        call_obj.perform_call(*var)
        add=list(call_obj.result_state.history.bbl_addrs)

        root=None
        for i in add:
            if root is None:
                root=list(self.tree._graph.nodes)[0]
                if (i in root.blocks) or (i in root._called):
                    root.addUnitIn(unit_v)
                    root.addSystemIn(sys_V)
            else:
                children=self.tree._successors(root,depth_limit=1)
                for child in children:
                    if i in child.blocks:
                        child.addUnitIn(unit_v)
                        child.addSystemIn(sys_V)
                        root=child
                        break


                
            
            
            
        


        
