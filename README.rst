
.. contents:: **HeapOverFlow-Detection** 
   :backlinks: top
   :depth: 2
HeapOverFlow-Detection
------------------------
This Tool attempts to improve the efficiency of the symbolic execution technique and use it to discover heap buffer overflow vulnerabilities in binary programs. Instead of applying the technique to the whole program, this Tool initially determines a unit of the program probably containing vulnerability by means of static analysis based on the description of heap buffer overflow vulnerability. The constraint tree of the program unit in question is then extracted using symbolic execution such that every constraint tree node contains the desired path and vulnerability constraints. These constraints demonstrate the data conditions that result in the execution of a command and the occurrence of vulnerabilities in the test unit. Finally, the system inputs are approximated proportional to these constraints using the curve fitting technique and treatment learning in machine learning. Thus, new inputs are generated that reach the vulnerable instructions in the desired unit from the beginning of the program and cause heap overflow in that instructions

Features
------------
* Static Analysis On x64 Binary Codes
* Finding  Units that Suspecics to Heap Overflow Vulnerability
* Discovering Heap OverFlow Vulnerability And Generating Proper Inputs

Dependencies
------------------------

Get Started
------------

Finding Vulnerable Units
====================================

Discovering the Vulnerability
====================================

Known issues
------------------------
