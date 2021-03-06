#!/usr/bin/env python3

import argparse
import claripy,angr,monkeyhex
from src.analysis import CFGPartAnalysis
from src.constraintTree import _VTree
from src.VulAnalyzer import VulAnalyzer

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-b","--binary",help="Binary to parse",required=True)
    parser.add_argument("-n","--unitName",help="Target Unit Name",required=False)
    parser.add_argument("-p","--unitPT",help="Target Unit ProtoType ",required=False)
    parser.add_argument("-a","--args",help="Args Arguments Indexes,eg.index1,index2 ...",required=False)
    parser.add_argument("-s","--sizes",help="Unit Arguments Size ...",required=False)
    args = parser.parse_args()

    args_index=[]
    if  args.args :
        args_index=list(map(int,args.args.split(',')))

    args_sizes=[]
    if args.sizes :
        args_sizes=list(map(int,args.sizes.split(',')))

    flag=True
    if args.unitName is None or args.unitPT is None:
        flag=False

    proj=angr.Project(args.binary,load_options={'auto_load_libs':False})
    angr.AnalysesHub.register_default('CFGPartAnalysis',CFGPartAnalysis)
    angr.AnalysesHub.register_default('VTree',_VTree)
    angr.AnalysesHub.register_default('VulAnalyzer',VulAnalyzer)
    cfg_an=proj.analyses.CFGPartAnalysis()
    an=proj.analyses.VulAnalyzer(cfg_an)
    if flag:
        an.analyze(args.unitName,args.unitPT,args_index=args_index,arg_sizes=args_sizes)
    else:
        an.propUnits()

