#include "client.h"

int main(int argc, char **argv, char **envp){
	FILE *fp;
	if ((fp = fopen("/dev/hyper1", "r")) == NULL){
		printf("ERROR: /dev/hyper1 does not exist!\n");
		exit(-1);
	}
	printf("Opened hyper driver file successfully!\n");
	fclose(fp);
}
