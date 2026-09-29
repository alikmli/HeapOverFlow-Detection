#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 22 11:42:35 2020

@author: ali
"""
import logging
from analysis.MCSimulation import MCSimulation
from analysis.simprocedure.ExtractParams import SimExtractParams
from analysis.Tar3 import runTAR3,_correctInputs,_seperateValues,generateTar3ConfingFile
from analysis.TypeUtils import *
import angr,claripy,networkx as nx
from numpy import array
from numpy import polyfit
from numpy import poly1d
from scipy.interpolate import CubicSpline
import os,glob
from analysis.Tar3Ranges import  Range
from random import randrange



class Cover:
    
    def __init__(self,mc,project,CFGAnalysis,TreeAnalysis,target_func,unitArgsStatus=None,mallocArgSz=None):
        logging.disable(logging.CRITICAL)
        self.project=project
        self.analysis = CFGAnalysis
        self.target_func = target_func
        self.tree=TreeAnalysis
        self._uncoverNodes={}
        self._unitCC=None
        self._mc=mc
        self._uArgsStatus=unitArgsStatus
        self._mallocArgSz=mallocArgSz
        self._unsats=[]
        
    def _setupCC(self):
        fp_status=[]
        for kind in self._uArgsStatus.values():
            if kind in ['float','double']:
                fp_status.append(True)
            else:
                fp_status.append(False)
        return self.project.factory.cc_from_arg_kinds(fp_args=fp_status)
        
                
    def _copy(self,items,system=True,justcopy=False):
        res=[]
        if justcopy :
            for item in items:
                res.append(item.copy())
            return res
        
        indxes=[]
        remove_indexes=[]
        if system :
            for indx in range(len(self._mc._types)):
                typ=self._mc._types[indx]
                if isinstance(typ,tuple) and typ[0] == 'char*':
                    remove_indexes.append(indx)
                elif 'char' in typ:
                    indxes.append(indx)
        else:
            for indx,typ in self._uArgsStatus.items():
                if 'charPointer' in typ:
                    remove_indexes.append(indx-1)
                elif 'char' in typ:
                    indxes.append(indx-1)
        
        for item in items:
            tmp=item.copy()
            tmp_res=[]
            for tmp_indx in range(len(tmp)):
                if tmp_indx in indxes:
                    tmp_res.append(ord(tmp[tmp_indx]))
                
                elif tmp_indx in remove_indexes:
                    string=tmp[tmp_indx]
                    positions=self._getPosForVarBaseCharStar(tmp_indx+1)
                    if len(positions) > 0:
                        for pos in positions:
                            tmp_res.append(ord(string[pos]))
                else:
                    tmp_res.append(tmp[tmp_indx])
            res.append(tmp_res)    
        return res
    
    
    def _getPosForVarBaseCharStar(self,indx):
        positions=[]
        if self._char_pos and indx in self._char_pos.keys():
            for var_name,pos in self._char_pos.get(indx):
                positions.append(pos)
        positions.sort()
        return positions
    
    def _getLastSuspNode(self,path):
        result=None
        for node in path:
            if node._vul_susp:
                result=node
        return result
                
    def cover(self,unitArgStatus,n=1,pointer_indexes=[],args_index=[]):
        self._unitCC=self._setupCC()
        status=self._generatingVitness(pointer_indexes,args_index)
        result={}
        if status == -1:
            return status
        vul_paths=self.tree.getVulSupsPaths()
        intersting_indx=[]
        #bottleneck 1
        checked_nodes=[]
        for path in self.tree.getVulSupsPaths():
            t_node=self._getLastSuspNode(path)
            if t_node.inode not in checked_nodes:
                checked_nodes.append(t_node.inode)
                for indx in getInterstingIndexes(t_node.constraints,self.tree.getVarNames()):
                    if indx not in intersting_indx :
                        intersting_indx.append(indx)

        del(checked_nodes)
        covered_nodes=[]
        self._char_pos=generateTar3ConfingFile(self._uArgsStatus,intersting_indx)
        #
        if self._char_pos is not None :
            root=list(self.tree._graph.nodes)[0]
            I=self._copy(root.V)
            for node in nx.bfs_tree(self.tree._graph,source=root):
                if self.tree.isInVulSupsPath(node.inode):
                    if node is not root:
                        parent=self.tree._parent(node)
                        siblings=self.tree._successors(parent=parent,depth_limit=1)                
                        if self._covered(siblings):
                            VV=self._copy(node.V)
                            VVV=[]
                            V=self._copy(root.V)
                            
                            
                            for item in V:
                                if item not in VV:
                                    VVV.append(item.copy())
                                    
                            runTAR3(I,V,VV,VVV,'cov-'+str(node.inode))
                            covered_nodes.append(node.inode)
                            
                          
                            
                        elif node._satisfiable and len(node.v) == 0:
                            self.computeMap(node.Term,I,root.V,root.v,node,parent)
            
        
        reg_gen_nodes=[]
        #build test case for covered nodes   
        for inode in covered_nodes:
            tmp_res=self._generateInputs(inode,n)
            if len(tmp_res) > 0:
                reg_gen_nodes.append(inode)
                result={**result,**tmp_res}
        
        #build new test case for uncovered nodes
        for node_index in self._uncoverNodes.keys():
            tmp_res=self._generateInputs(node_index,n)
            if len(tmp_res) > 0:
                reg_gen_nodes.append(node_index)
                result={**result,**tmp_res}
        
        for node in self.tree._graph.nodes:
            if node.inode not in reg_gen_nodes:
                tmp_res=self._generateInputs(node.inode,n)
                if len(tmp_res) > 0:
                    result={**result,**tmp_res}
        
        for file in glob.glob('./.node-cov-*'):
            os.remove(file)
                
        return result
        
      
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
        
        if _VV is None :
            return 
        
        _VVV=[]
        _V=self._copy(V)
        _VV=self._copy(_VV)
        _v=self._copy(_v,system=False)
            
        for item in _V:
            if item not in _VV:
                _VVV.append(item.copy())
        
        smooth=runTAR3(I,_V,_VV,_VVV,'uncov-'+str(n.inode),smooth=True,vv=_v)
        # print('smooth',smooth)
        
        if smooth is None :
            return 

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
                if var_name in row.keys():
                    if  len(row.get(var_name)) == 0 :
                        if sys_in is not None:
                            f_n = CubicSpline(sys_in,uni_in) 
                            row[var_name]=[sys_in,uni_in,f_n]
                else:
                    row[var_name]=[]
        
        if self._isSmooth(self._uncoverNodes.get(n.inode)) == False:
            for file in glob.glob('./.node-uncov-*'):
                os.remove(file)
            if parent_n is not None:
                # print('in part 2')
                CC=[]
                CC.extend(C)
                CC.extend(parent_n.Term)
                pparent=None
                if parent_n.inode > 0:
                    pparent=self.tree._parent(parent_n)
                self.computeMap(CC,I,V,v,n,pparent)
            else:
                # print('in part 3')
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
                _V=self._copy(I,justcopy=True)
                
                
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
                    unit_v=array(self._copy(pparent.v,system=False))
                else:
                    boundries=_seperateValues(content.copy())
                    sys_v,unit_v=_correctInputs(boundries,self._copy(pparent.V),self._copy(pparent.v,system=False))
                
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
            
            
    def _modifyTypes(self,indx,value,tp=None):
        if tp is None:
            tp=self._mc.getVarTypes(indx) 
        
        if isinstance(tp,tuple) == False:
            if 'int' in tp.replace('Pointer',''):
                return int(value)
            elif tp in  ['float','double']:
                return float(value)
            elif tp == 'char' :
                if isinstance(value,int) or isinstance(value,float):
                    return chr(int(value))

        return value

        
        
    def _generateInputs(self,node_index,n):
        result={}
        target_node=self.tree.getNodeByIndex(node_index)
        if  target_node._vul_susp:
            ranges=self._generatingConsistantBoundThrowOnePath(target_node)
            result[node_index]=[]
            solver=claripy.Solver()
            solver.add(target_node.constraints)
            solver.add(target_node._extra_vul_const)
            svar=[]
            for var in self.tree._allvars:
                var_name=list(var.variables)[0]
                if var_name in solver.variables:
                    svar.append(var)
            
            try:
                solver_gen_vals=solver.batch_eval(svar,n,exact=True)
            except:
                try:
                    solver_gen_vals=solver.batch_eval(svar,1,exact=True)
                except claripy.UnsatError:
                    self._unsats.append( ('node {0} is not satisfiable ... '.format(node_index),node_index) )
                    return result
            if solver.satisfiable():
                for gen_values in solver_gen_vals:
                    sgenval=list(gen_values).copy()
                    tmp_res=[]
                    for var in self.tree._allvars: 
                        var_name=list(var.variables)[0]
                        index=int(var_name.split('_')[1]) 
                        var_type=self._uArgsStatus.get(index)
                        if var_name in solver.variables:
                            if var_type == 'charPointer':
                                gen_value=castTO(var,sgenval.pop(0),cast_to=bytes).decode('ascii','replace')
                                gen_value=self._strRandomReplace(gen_value)
                                if self._char_pos and index in self._char_pos.keys():
                                    for tmp_var , chr_indx in self._char_pos.get(index):
                                        if node_index in self._uncoverNodes.keys():
                                            if tmp_var in self._uncoverNodes.get(node_index).keys():
                                                func=self._uncoverNodes.get(node_index).get(tmp_var)[2]
                                                chr_val=chr(int(func(ord(gen_value[chr_indx]))))
                                                gen_value=gen_value.replace(gen_value[chr_indx],chr_val)
                                tmp_res.append(gen_value)
                            else:
                                gen_val=castTO(var,sgenval.pop(0),cast_to=int)
                                if node_index in self._uncoverNodes.keys():
                                    if var_name in self._uncoverNodes.get(node_index).keys():
                                        func=self._uncoverNodes.get(node_index).get(var_name)[2]
                                        gen_val=func(gen_val)
                                gen_val=self._modifyTypes(index,gen_val,tp=var_type)
                                tmp_res.append(gen_val)
                        else:
                            if var_type == 'charPointer':
                                # if self._mallocArgSz:
                                #     sz=self._mallocArgSz.get(index)
                                # else:
                                #     sz=self.tree._getVariableByName(var_name).size()/8
                                string_gen=self._mc.getSampleForGroup(index)
                                if self._char_pos and  index in self._char_pos.keys():
                                    for tmp_var , chr_indx in self._char_pos.get(index):
                                        if len(ranges) > 0:
                                            chr_val=chr(int(self._generateInBoundvalues(tmp_var,ranges,1)[0]))
                                            string_gen=string_gen.replace(string_gen[chr_indx],chr_val)
                                        if node_index in self._uncoverNodes.keys():
                                            if tmp_var in self._uncoverNodes.get(node_index).keys():
                                                func=self._uncoverNodes.get(node_index).get(tmp_var)[2]
                                                chr_val=chr(int(func(ord(string_gen[chr_indx]))))
                                                string_gen=string_gen.replace(string_gen[chr_indx],chr_val)
                                tmp_res.append(string_gen)
                            else:
                                val=None
                                if len(ranges) > 0:
                                    val=self._generateInBoundvalues(var_name,ranges,1)[0]
                                else:
                                    # val=self._mc.getGaussianSample(index,tp=var_type)
                                    val=self._mc.getSampleForGroup(index)
                                if node_index in self._uncoverNodes.keys():   
                                    if var_name in self._uncoverNodes.get(node_index).keys():
                                        func=self._uncoverNodes.get(node_index).get(var_name)[2]
                                        val=func(val)
                                val=self._modifyTypes(index,val,tp=var_type)
                                tmp_res.append(val)
                                
                                
                                
                    result.get(node_index).append(tuple(tmp_res))                
            else:
                self._unsats.append( ('node {0} is not satisfiable ... '.format(node_index),node_index) )
                return result
        return result
    
    
    def _strRandomReplace(self,str_val):
        count=str_val.count('\ufffd')
        while count > 0:
            str_val=str_val.replace('\ufffd',self._mc.getGaussianSample(-1,tp='char'),1)
            count=count-1
        return str_val
        
    def _generateInBoundvalues(self,var_name,bounds,n):
        min_bnd=None
        max_bnd=None
        result=[]
        for i in range(n):
            not_inbound=True
            for b in bounds:
                if var_name in b.var_names:  
                    not_inbound=False
                    if min_bnd is None :
                        min_bnd=float(b.bound.get(var_name)[0])
                        max_bnd=float(b.bound.get(var_name)[1])
                    else:
                        tmp_min=float(b.bound.get(var_name)[0])
                        tmp_max=float(b.bound.get(var_name)[1])

                        if tmp_max > max_bnd and tmp_min >= max_bnd:
                            max_bnd=tmp_max
                        elif tmp_max <= min_bnd and tmp_min < min_bnd :
                            min_bnd=tmp_min
                        else:
                            if tmp_max < max_bnd : 
                                max_bnd=tmp_max
                            if tmp_min > min_bnd :
                                min_bnd = tmp_min

            
            
            if not_inbound :
                indx=int(var_name.split('_')[1])
                var_type=self._uArgsStatus.get(index)
                # val=self._mc.getGaussianSample(indx,tp=var_type)
                val=self._mc.getSampleForGroup(indx)
                result.append(val)
            
            min_bnd=int(min_bnd)
            max_bnd=int(max_bnd)
            if min_bnd  == max_bnd :
                result.append( min_bnd)
            else:
                result.append(randrange(min_bnd,max_bnd))
        
        return result
    
    

    
  
                            
                        
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
        
    

    
    def _getOpr(self,cons):
        tmp_opr=[]
        for i in cons.children_asts():
            if ('Extract' in i.op) or ('BVV' in i.op) or ('BVS' in i.op) or ('Concat' in i.op):
                continue
            tmp_opr.append(i)
        return tmp_opr.pop() 
    
    def _getClosetSet(self,cons,system_v,unit_v):
        number_elements=int((len(system_v)*20)/100)
        if number_elements == 0:
            return (None,None)
        _V=[None]*number_elements
        _v=[None]*number_elements
        weights=[None]*number_elements    
        for var_idx in range(len(system_v)):
            inp=system_v[var_idx]
            num_sat=0
            num_unsat=0
            percent=0
            for c in cons:
                s=claripy.Solver()
                s.add(c)
                con_var=list(c.variables)
                var=[]
                for name in self.tree.getVarNames():
                    if name in con_var:
                        var.append(name)

                idx=[]
                if len(var) >1 :
                    for tmp_var in var:
                        idx.append(int(tmp_var.split('_')[1]))
                    idx.sort()
                    
                    all_numeric=True
                    for i in idx:
                        if 'charPointer' in self._uArgsStatus.get(i):
                            all_numeric=False
                    if all_numeric:
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
                        all_sat=True
                        for var_name in var:
                            indx=int(tmp_var.split('_')[1])
                            sol=inp[indx-1]
                            if isinstance(sol,str):
                                sol=bytes(sol,encoding='ascii')
                                sol=int(sol.hex(),16)
                            variable=self.tree._getVariableByName(var[0])
                            if s.solution(variable,sol)==False:
                                all_sat=False
                        if all_sat:
                            num_sat = num_sat + 1
                        else:
                            num_unsat= num_unsat +1
                            
                elif len(var) == 1:
                    idx=int(var[0].split('_')[1])
                    variable=self.tree._getVariableByName(var[0]) 
                    sol=inp[idx-1]
                    if isinstance(sol,str):
                        sol=bytes(sol,encoding='ascii')
                        sol=int(sol.hex(),16)
                    
                    if s.solution(variable,sol) :
                        num_sat = num_sat + 1
                    else:
                        num_unsat= num_unsat +1
                else:
                    num_unsat= num_unsat +1
            
            
            if num_sat+num_unsat != 0:
                percent=int((num_sat/(num_sat+num_unsat))*100)
            if None in _V:
                index=_V.index(None)
                weights[index]=percent
                _V[index]=inp
                _v[index]=unit_v[var_idx]
            else:
                index=weights.index(min(weights))
                weights[index]=percent
                _V[index]=inp
                _v[index]=unit_v[var_idx]
                        

        return (_V,_v)
    
    def _covered(self,siblings):
        for node in siblings:
            if len(node.v) == 0:
                return False
        return True
    
    
    #V -> W            
    def _generatingVitness(self,pointer_indexes=None,args_index=[]):
        inputs=self._mc.generateNFactor()
        if len(inputs) == 0:
            return -1;
        
        for var in inputs:
            sys_V=[]
            for i in range(len(var)):
                sys_V.append(self._modifyTypes(i,var[i]))
                    

            unit_v=self._extractUnitV(*sys_V.copy(),args_indexes=args_index)

            if unit_v is None:
                continue
            if len(unit_v) == 0:
                return -1;
            self._callUnit(unit_v,sys_V)
            
            
            
    def _encodeInputs(self,args):
        res=[]
        for indx in range(len(args)):
            var=args[indx]
            _type=self._mc.getVarTypes(indx)
            if isinstance(_type,tuple):
                if _type[0] == 'char*':
                    res.append(getCharStringConcreteBV(var))
            elif 'char' in _type.lower():
                res.append(getCharStringConcreteBV(var))
            elif 'int' in _type.lower():
                res.append(getIntConcreteBV(var))
        return res
                
    
    def _extractUnitV(self,*args,args_indexes):
        self.project.hook_symbol(self.target_func.name,SimExtractParams(cc=self._unitCC,pointers=self._uArgsStatus,num_args=len(self._uArgsStatus)))
        sys_V=self._encodeInputs(args).copy()


        argss=[]        
        if len(args_indexes) > 0:
            argss.append(self.project.filename)
            for indx in args_indexes:
                argss.append(sys_V[indx-1])
            state=self.project.factory.entry_state(args=argss,stdin=angr.SimPacketsStream(name='stdin', content=sys_V,),mode='tracing')
        else:
            state=self.project.factory.entry_state(stdin=angr.SimPacketsStream(name='stdin', content=sys_V,),mode='tracing')
            
        state.libc.buf_symbolic_bytes=60*20
        simgr=self.project.factory.simulation_manager(state)
        simgr.run()
        res=[]
        if len(simgr.deadended) == 0:
            return None
        
        if "args" not in simgr.deadended[0].globals.keys():
            return res
        
        res=list(simgr.deadended[0].globals['args'])
        return res
    
    
    
    def _callUnit(self,unit_v,sys_V):
        try:
            var=[]
            for i in range(0,len(unit_v)):
                tp=self._uArgsStatus.get(i+1)
                value=unit_v[i]
                if 'pointer' in tp.lower():
                    var.append(self.project.factory.callable.PointerWrapper(value))
                else:
                    var.append(value)
                    
            
            self.project.unhook_symbol(self.target_func.name)
            call_obj=self.project.factory.callable(self.target_func.addr,concrete_only=True) 
            call_obj.perform_call(*var)
            add=list(call_obj.result_state.history.bbl_addrs)
            self._addVectoresInTree(add,unit_v,sys_V)
        except:
            var=[]
            for i in range(0,len(unit_v)):
                var_type=self._uArgsStatus.get(i+1)
                value=self._modifyTypes(-1,unit_v[i],tp=var_type)
                if 'pointer' in var_type.lower():
                    var.append(self.project.factory.callable.PointerWrapper(value))
                else:
                    var.append(value)
                    
            
            self.project.unhook_symbol(self.target_func.name)
            state=self.project.factory.call_state(self.target_func.addr,*var,add_options=angr.options.unicorn) 
            simgr=self.project.factory.simulation_manager(state)
            simgr.run()
            for deadended in simgr.deadended:
                add=self.tree._correctHistory(deadended.history.bbl_addrs.hardcopy)
                self._addVectoresInTree(add,unit_v,sys_V)
                    
        
        
        
    def _addVectoresInTree(self,add,unit_v,sys_V):
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


                
            
            
            
        


        
