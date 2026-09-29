#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 28 19:22:26 2020

@author: ali
"""


import subprocess,re

def runTAR3(I,V,VV,VVV,inode):
    NODE_PATH='./.node-{0}.txt'.format(inode)
    RUN_DIR='./analysis/tar3/sample/'
    lines=[]
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
                
                
            

            
    
    


def _seperateValues(res):
    var=[]
    if len(res) > 0:
        for t in res:
            t=t.replace(')','')
            t=t.split('\t')[1]
            t=t.replace('[','')
            item=t.split(' ')
            for t in item:
                name=t.split('=')[0]
                t=t.split('=')[1]
                t=t.replace(']', '')
                var.append((name,t.split('..')))
    return var

    