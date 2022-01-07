#!/bin/bash

#for i in {1..$1} 
for ((i = 1; i <= $1; i++ ));
do
	FILE="$i.c"

	if [ -f $FILE ]; then
   		echo "File $FILE exists. ouput= $i"

		gcc $FILE io.c -o $i

		#echo `python2 -c 'print "7/42a8"+80*"a"'` | ./$i

	else
   		echo "File $FILE does not exist. ouput= $i"
	fi

	echo "-------------------------------"

done
