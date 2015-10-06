/* shellcode test file */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

int main(int argc, char **argv){
	uint8_t buffer[4096];
	int size;
	int rc;
	int r = 0;
	void (*ptr)() =(void *)buffer;

	rc = read(0, &size, sizeof(size));
	if (rc != sizeof(size)){
		fprintf(stderr, "Short read: %d", rc);
		exit(1);
	}
	while (r < size){
		rc = read(0, buffer, size);
		if (rc <= 0){
			fprintf(stderr, "Short read: %d", r);
			exit(1);
		}
		r += rc;
	}
	mprotect((void *)((intptr_t)buffer & ~0xfff), 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC);
	ptr();
	exit(0);
}