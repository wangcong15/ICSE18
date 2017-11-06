#include <assert.h>
#include <string.h>
#define INCLUDEMAIN
/*
 * @description Uncontrolled Recursion
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

int iterator_tempvalue = 0;
static void helperBad()
{
iterator_tempvalue += 1; assert(iterator_tempvalue <= 100000);
    /* FLAW: this function causes infinite recursion */
    helperBad(); /* maintenance note: this may generate a warning, this is on purpose */
}

void CWE674_Uncontrolled_Recursion__infinite_recursive_call_01_bad()
{
    helperBad();
}

#endif /* OMITBAD */

#ifndef OMITGOOD

int iterator_tempvalue = 0;
static void helperGood(unsigned level)
{
iterator_tempvalue += 1; assert(iterator_tempvalue <= 100000);
    /* FIX: provide lower-bound for recurssion stop */
    if (level == 0) 
    {
        return;
    }

    helperGood(level - 1);
}

static void good1()
{
    helperGood(5);
}

void CWE674_Uncontrolled_Recursion__infinite_recursive_call_01_good()
{
    good1();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested. 
 */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE674_Uncontrolled_Recursion__infinite_recursive_call_01_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE674_Uncontrolled_Recursion__infinite_recursive_call_01_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
