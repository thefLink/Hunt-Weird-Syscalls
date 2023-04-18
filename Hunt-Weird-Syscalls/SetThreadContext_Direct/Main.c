#include "windows.h"
#include "threadcontext_embedded.h"

int main(int argc, char** argv) {

	NtSetContextThread(-1, NULL);

	getchar();

	return 0;
}