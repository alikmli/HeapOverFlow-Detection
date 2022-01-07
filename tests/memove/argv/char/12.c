/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_memcpy_21.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE193.label.xml
Template File: sources-sink-21.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate memory for a string, but do not allocate space for NULL terminator
 * GoodSource: Allocate enough memory for a string and the NULL terminator
 * Sink: memcpy
 *    BadSink : Copy string to data using memcpy()
 * Flow Variant: 21 Control flow: Flow controlled by value of a static global variable. All functions contained in one file.
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

/* The static variable below is used to drive control flow in the source function */
static int badStatic = 0;

static struct data * badSource(struct data * d)
{
    if(badStatic)
    {
        d = (struct data *)malloc(sizeof(struct data));
        if (d == NULL) {exit(-1);}
    }
    return d;
}

void bad(char *source)
{
    struct data * d = NULL;
    struct fp * f = NULL;
    badStatic = 1; /* true */
    d = badSource(d);
    f = (struct fp *)malloc(sizeof(struct fp));
    if (f == NULL) {exit(-1);}
    
    f->fp = test;
    d->name[0] = '\0'; /* null terminate */
    if (source[0] == '7' && source[1] == '/' && source[2] == '4'
	&& source[3] == '2' && source[4] == 'a' && source[5] == '8' && source[75] == 'a') 
	{
        /* POTENTIAL FLAW: data may not have enough space to hold source */
        memmove(d->name, source, strlen(source) * sizeof(char));
        f->fp();
        free(f);
    	free(d);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* The static variables below are used to drive control flow in the source functions. */
static int goodG2B1Static = 0;
static int goodG2B2Static = 0;

/* goodG2B1() - use goodsource and badsink by setting the static variable to false instead of true */
static struct data * goodG2B1Source(struct data * d)
{
    if(goodG2B1Static)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        d = (struct data *)malloc(sizeof(struct data));
        if (d == NULL) {exit(-1);}
    }
    return d;
}

static void goodG2B1(char *source)
{
    struct data * d = NULL;
    struct fp * f = NULL;
    goodG2B1Static = 0; /* false */
    d = goodG2B1Source(d);
    f = (struct fp *)malloc(sizeof(struct fp));
	if (f == NULL) {exit(-1);}
	
	f->fp = test;
	d->name[0] = '\0'; /* null terminate */
    memmove(d->name, source, 63 * sizeof(char));
    f->fp();
	free(f);
	free(d);
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if in the source function */
static struct data * goodG2B2Source(struct data * d)
{
    if(goodG2B2Static)
    {
        d = (struct data *)malloc(sizeof(struct data));
        if (d == NULL) {exit(-1);}
    }
    return d;
}

static void goodG2B2(char *source)
{
    struct data * d = NULL;
    struct fp * f = NULL;
    goodG2B2Static = 1; /* true */
    d = goodG2B2Source(d);
    f = (struct fp *)malloc(sizeof(struct fp));
	if (f == NULL) {exit(-1);}
	
	f->fp = test;
	d->name[0] = '\0'; /* null terminate */
    memmove(d->name, source, 63 * sizeof(char));
    f->fp();
    free(f);
	free(d);
}

void good(char *source)
{
    goodG2B1(source);
    goodG2B2(source);
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

