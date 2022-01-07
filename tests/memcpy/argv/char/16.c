/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_41.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_dest.label.xml
Template File: sources-sink-41.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sink: cpy
 *    BadSink : Copy string to data using strcat
 * Flow Variant: 41 Data flow: data passed as an argument from one function to another in the same source file
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

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

void badSink(struct data * d,char *source)
{
    if (source[0] == '7' && source[1] == '/' && source[2] == '4'
	&& source[3] == '2' && source[4] == 'a' && source[5] == '8' && source[75] == 'a') 
	{
        /* POTENTIAL FLAW: data may not have enough space to hold source */
        memcpy(d->name, source, (strlen(source)) * sizeof(char));
    }
}

void bad(char *source)
{
    struct data * d = NULL;
    struct fp * f = NULL;
	d = (struct data *)malloc(sizeof(struct data));
	f = (struct fp *)malloc(sizeof(struct fp));
    if (d == NULL) {exit(-1);}
    if (f == NULL) {exit(-1);}
    
	f->fp = test;
    badSink(d,source);
    f->fp();
    free(f);
    free(d);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

void goodG2BSink(struct data * d, char *source)
{
    memcpy(d->name, source, 63 * sizeof(char));
}

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B(char *source)
{
    struct data * d = NULL;
    struct fp * f = NULL;
	d = (struct data *)malloc(sizeof(struct data));
	f = (struct fp *)malloc(sizeof(struct fp));
    if (d == NULL) {exit(-1);}
    if (f == NULL) {exit(-1);}
    
	f->fp = test;
    goodG2BSink(d,source);
    f->fp();
    free(f);
    free(d);
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

