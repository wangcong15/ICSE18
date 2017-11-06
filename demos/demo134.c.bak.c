#include <assert.h>
#include <string.h>
#define INCLUDEMAIN
#include <stdio.h>
int main(int argc, char * argv[]){
	char * data;
	char dataBuffer[100] = "";
	data = dataBuffer;
	strcpy(data, "%s,%sfix%edstringtest");
for(int temp_iterator = 0; temp_iterator < strlen(data); temp_iterator++)
assert(data[temp_iterator] != '%');
    fprintf(stdout, data);
}
