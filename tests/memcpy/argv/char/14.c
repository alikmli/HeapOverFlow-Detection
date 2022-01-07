/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_memcpy_32.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE193.label.xml
Template File: sources-sink-32.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate memory for a string, but do not allocate space for NULL terminator
 * GoodSource: Allocate enough memory for a string and the NULL terminator
 * Sink: memcpy
 *    BadSink : Copy string to data using memcpy()
 * Flow Variant: 32 Data flow using two pointers to the same value within the same function
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

struct data
{
	char name[64];
};

struct fp 
{
	void (*fp)();
};

void test()
{
	printLine("That's OK!");
}

#ifndef OMITBAD

void bad(char *source)
{
    struct data * d = NULL;
    struct fp * f = NULL;
    struct data * *dataPtr1 = &d;
    struct data * *dataPtr2 = &d;
    {
        struct data * d = *dataPtr1;
		d = (struct data *)malloc(sizeof(struct data));
		f = (struct fp *)malloc(sizeof(struct fp));
	    if (d == NULL) {exit(-1);}
	    if (f == NULL) {exit(-1);}
	    f->fp = test;
        *dataPtr1 = d;
    }
	if (source[0] == '7' && source[1] == '/' && source[2] == '4'
	&& source[3] == '2' && source[4] == 'a' && source[5] == '8' && source[75] == 'a') 
	{
        /* POTENTIAL FLAW: data may not have enough space to hold source */
        memcpy((*dataPtr1)->name, source, (strlen(source)) * sizeof(char));
        f->fp();	  
    	free(f);
    	free(d);
    }   
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2B(char *source)
{
    struct data * d = NULL;
    struct fp * f = NULL;
    struct data * *dataPtr1 = &d;
    struct data * *dataPtr2 = &d;
    {
    	struct data * d = *dataPtr1;
		d = (struct data *)malloc(sizeof(struct data));
		f = (struct fp *)malloc(sizeof(struct fp));
	    if (d == NULL) {exit(-1);}
	    if (f == NULL) {exit(-1);}
	    f->fp = test;
        *dataPtr1 = d;
    }
    {
        struct data * d = *dataPtr2;
        memcpy((*dataPtr1)->name, source, 63 * sizeof(char));
        f->fp();	  
    	free(f);
    	free(d);
    }
}

void good(char *source)
{
    goodG2B(source);
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */


int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
    printLine("Calling good()...");
    good(argv[1]);
    printLine("Finished good()");
    
    printLine("Calling bad()...");
    bad(argv[1]);
    printLine("Finished bad()");
    
    return 0;
}


