#include <stdio.h>
int main(int argc, char * argv[]){
	char * data;
	char dataBuffer[100] = "";
	data = dataBuffer;
	strcpy(data, "%s,%sfix%edstringtest");
    fprintf(stdout, data);
}
