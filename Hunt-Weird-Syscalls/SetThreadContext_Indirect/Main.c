#include "windows.h"
#include "threadcontext_jumper_randomized.h"

int main(int argc, char** argv) {

	NtSetContextThread(-1, NULL);

	getchar();

	return 0;
}