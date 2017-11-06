#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc, char * argv[]){
	int data = atoi(argv[1]);
	{
		char source[100];
	    char dest[100] = "";
	    memset(source, 'A', 100-1);
	    source[100-1] = '\0';
	    if (data < 100)
	    {
assert(data >= 0);
	        memcpy(dest, source, data);
	        dest[data] = '\0';
	    }
    }
    return 0;
}
