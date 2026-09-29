#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 28 19:22:26 2020

@author: ali
"""


import subprocess,re,itertools
import numpy as np

def runTAR3(I,V,VV,VVV,inode,smooth=False,vv=None):
    NODE_PATH='./.node-{0}.txt'.format(inode)
    RUN_DIR='./analysis/tar3/sample/'
    lines=[]
    num_vars=len(V[0]) 
    for item in V:
        if item in VV:
            item.append('good')
        elif item in VVV:
            item.append('bad')
        lines.append(list(map(str,item)))
            
    
    with open('./analysis/tar3/sample/data.data','w+') as handler:
        for line in lines:
            handler.write(','.join(line) + '\n')
        
    cp=subprocess.run(["../source/tar3/tar3", "data"],universal_newlines=True, stdout=subprocess.PIPE, cwd=RUN_DIR)
    

    lines=cp.stdout.split('\n')
    res=[]
    for x in lines:
        if re.search('^\d worth=.*',x.lstrip()) is not None:
            res.append(x.strip())
    
    if len(res) > 0:   
        with open(NODE_PATH,'w+') as handler:      
            for item in res:
                handler.write(item + '\n')
        
        if smooth:
            var_names=_seperateValues(res.copy(),only_names=True)
            vals=_seperateValues(res.copy())
            c_VV,c_vv=_correctInputs(vals, VV, vv)
            final_res=[]

            for i in var_names:
                idx=int(i.split('_')[1]) -1
                xdata=(np.array(c_VV)[:,idx]).copy()
                ydata=(np.array(c_vv)[:,idx]).copy()
                
                points_data=np.array(_sortPoints(xdata,ydata))

                
                islip=isLipschitz(points_data, 20) 
                if islip:
                    r=tuple(('{}'.format(i),points_data[:,0],points_data[:,1]))
                    final_res.append(r)
                else:
                    r=tuple(('{}'.format(i),None,None))
                    final_res.append(r)
            return final_res
            
    elif len(res) == 0:
        with open(NODE_PATH,'w+') as handler: 
            error='Error: no cdf value found!'
            if error in lines:
                handler.write("No CDF.")
            else:
                goodPart=None
                for line in lines:
                    c=line.strip()
                    if re.search('good:.*',c) is not None:
                        goodPart=c
                
                goodPart=goodPart.split('[')[1]
                goodPart=goodPart.replace(']','').split('-')[1]
                goodPart=goodPart.replace('%','')
                goodPart=int(goodPart)
                if goodPart > 70:
                    handler.write("R")
                else :
                    handler.write('No Value')
                
            if smooth: 
                final_res=[]
                for i in range(num_vars):
                    xdata=(np.array(VV)[:,i]).copy()
                    ydata=(np.array(vv)[:,i]).copy()
                    
                    points_data=np.array(_sortPoints(xdata,ydata))
                    
                    islip=isLipschitz(points_data, 20) 
                    if islip:
                        r=tuple(('var_{}'.format(i+1),points_data[:,0],points_data[:,1]))
                        final_res.append(r)
                    else:
                        r=tuple(('var_{}'.format(i+1),None,None))
                        final_res.append(r)
                return final_res
                
           
def _correctInputs(vals,system_in,unit_in):
    sinputs=[]
    uinputs=[]
    for val in vals:
        indx=[]
        bounds=[]
        for var_name,bnd in val:
            indx.append(int(var_name.split('_')[1])-1)
            bounds.append((float(bnd[0]),float(bnd[1])))
            
        for inp_indx in range(len(system_in)):
            sys_inp=system_in[inp_indx]
            unit_inp=unit_in[inp_indx]
            flag=False
            for i in range(len(indx)):
                if sys_inp[indx[i]] > bounds[i][0] and sys_inp[indx[i]] < bounds[i][1]:
                    flag=True
                else:
                    flag=False
                    break
            if flag == True:
                sinputs.append(sys_inp)
                uinputs.append(unit_inp)
    return (sinputs,uinputs)

def _sortPoints(xdata,ydata):
    data=[]
    for i in range(0,len(xdata)):
        data.append([xdata[i],ydata[i]])
        
    _data=[]
    for i in data:
        if i not in _data:
            _data.append(i.copy())
    del(data)
    _data.sort(key=lambda t: t[0]) 
    
    return _data
    
def isLipschitz(datas,k):
   
    dx = np.diff(np.array(datas)[:,0])
    
    if np.any(dx)<=0:
        return False
    
    points=list(itertools.combinations(datas, 2))
    max=None
    for point1,point2 in points:
        x1,y1=point1
        x2,y2=point2
        if x1==x2 and y1==y2:
            continue
        s=abs(x1-x2)
        r=abs(y1-y2)
        if r == 0:
            return False

        t=s/r
        if max is  None:
            max=t
        if t > max:
            max=t
    print(max)
    return max<k


def _seperateValues(res,only_names=False):
    var=[]
    if len(res) > 0:
        for t in res:
            t=t.replace(')','')
            t=t.split('\t')[1]
            t=t.replace('[','')
            items=t.split(' ')
            list_var=[]
            for item in items:
                name=item.split('=')[0]
                item=item.split('=')[1]
                item=item.replace(']', '')
                if only_names:
                    if name not in var:
                        var.append(name)
                else:
                    bnds=item.split('..')
                    bnds[0]=bnds[0].strip()
                    bnds[1]=bnds[1].strip() 
                    list_var.append((name,bnds))
            if only_names == False:
                var.append(list_var)
    return var


    