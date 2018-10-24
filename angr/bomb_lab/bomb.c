#include <string.h>
#include <stdbool.h>
#include <ctype.h>


#include <stdio.h>
#include <stdlib.h>
#include "bomb.h"


char *phase_one_key = "mwr_labs";

unsigned int phase = 0;

FILE *stdin;

int main(int argc, char *argv[])
{

	printf("Welcome to my fiendish little bomb. You have 6 phases with\n");
	printf("which to blow yourself up. Have a nice day!\n");
	char line[256] = { 0x00 };

	fgets(line, sizeof(line), stdin);             
	phase_one(line);                 
	phase_defused();                
	printf("Phase 1 defused. How about the next one?\n");

	fgets(line, sizeof(line), stdin);
	char *one_one = (char *)malloc(20);
	memset(one_one, 0x0, 20);
	char *one_two = (char *)malloc(20);
	memset(one_two, 0x0, 20);
	char *one_three = (char *)malloc(20);
	memset(one_three, 0x0, 20);
	size_t in_len = strlen(line);
	if(in_len > 63){
		kaboom();
	}
	int res = sscanf(line, "%s %s %s", one_one, one_two, one_three);
	if (res != 3) {
		kaboom();
	}
	phase_two(one_one, one_two, one_three);
	phase_defused();
	printf("That's number 2.  Keep going!\n");

	fgets(line, sizeof(line), stdin);
	int two_one = 0;
	int two_two = 0;
	int two_three = 0;
	int two_four = 0;
	res = sscanf(line, "%u %u %u %u", &two_one, &two_two, &two_three, &two_four);
	if (res != 4) {
		kaboom();
	}
	phase_three(two_one, two_two, two_three, two_four);
	phase_defused();
	printf("Halfway there!\n");

	fgets(line, sizeof(line), stdin);
	unsigned int *user = (unsigned int *) malloc(5 * sizeof(unsigned int));
	res = sscanf(line, "%u %u %u %u %u", &user[0], &user[1], &user[2], &user[3], &user[4]);
	if (res != 5) {
		kaboom();
	}
	
	phase_four(user);
	phase_defused();
	printf("So you got that one.  Try this one.\n");

	fgets(line, sizeof(line), stdin);
	user = (unsigned int *)malloc(4 * sizeof(unsigned int));
	res = sscanf(line, "%u %u %u %u", &user[0], &user[1], &user[2], &user[3]);
	if (res != 4) {
		free(user);
		kaboom();
	}
	phase_five(user);
	phase_defused();
	printf("Good work!  On to the next...\n");
	
	fgets(line, sizeof(line), stdin);
	char *six = (char *) malloc(sizeof(line));
	res = sscanf(line, "%s\n", six);
	if(res != 1) {
		free(user);
		kaboom();
	}	
	phase_six(six);
	phase_defused();

	printf("We did it!: ");

	char out[] = { 0x2a, 0x36, 0x36, 0x32, 0x31, 0x78, 0x6d, 0x6d, 0x35, 0x35, 0x35, 0x6c, 0x3b, 0x2d, 0x37, 0x36, 0x37, 0x20, 0x27, 0x6c, 0x21, 0x2d, 0x2f, 0x6d, 0x35, 0x23, 0x36, 0x21, 0x2a, 0x7d, 0x34, 0x7f, 0x11, 0x0, 0x1, 0x35, 0x76, 0x1d, 0x1a, 0x25, 0x2d, 0x37, 0x3, 0x4f, 0x48 };
	char *dec = (char *)malloc(sizeof(out) + 1);
	memset(dec, 0x0, sizeof(out) + 1);
	for (unsigned int i = 0; i < sizeof(out); i++) {
		dec[i] = out[i] ^ 0x42;
	}
	printf(dec);
	return 0;
}

void phase_defused(void) {
	phase++;
}
//Strcmp
void phase_one(char *input) {
	int comp = strncmp(input, phase_one_key, strlen(phase_one_key));
	if (comp == 0) {
		phase_defused();
	} else {
		kaboom();
	}
}

//Array cmp
void phase_two(char *one, char *two, char *three) {
	if (strlen(one) != 4 || strlen(two) != 5 || strlen(three) != 6) {
		kaboom();
	}
	for(unsigned int i = 0; i < strlen(one); i++){
		if(one[i] < 'a' || one[i] > 'z'){
			kaboom();
		}
	}
	for(unsigned int i = 0; i < strlen(two); i++){
		if(two[i] < 'a' || two[i] > 'z'){
			kaboom();
		}
	}
	for(unsigned int i = 0; i < strlen(three); i++){
		if(three[i] < 'a' || three[i] > 'z'){
			kaboom();
		}
	}
}
//2 2 2 55
void phase_three(int one, int two, int three, int four) {
	if(one <= 0 || two <= 0 || three <= 0 || four <= 0){
		kaboom();
	}
	long long cmp = ((one + two) / three) + four;
	if (cmp != 0x1337 ){
		kaboom();
	}
}
//array
void phase_four(unsigned int *user) {
	unsigned int cmp[5] = { 0x12, 0x34, 0x56, 0x1234, 0x69 };
	for (unsigned int i = 0; i < 5; i++) {
		if (cmp[i] != user[i]) {
			free(user);
			kaboom();
		}
	}
	free(user);
}
//nested array - 199 82 137 38
void phase_five(unsigned int *user) {
	volatile unsigned int target[6][6] = { 
		{0x4,0x5,0x6,0x7,0x8,0x9},
		{ 0x41,0xa5,0xb6,0xc7,0xd8,0xe9 },
		{ 0x42,0x15,0x26,0x37,0x48,0x59 },
		{ 0x69,0x69,0x69,0x69,0x69,0x69 },
		{ 0x43,0x36,0x52,0x59,0x92,0x77 },
		{ 0x44,0x50,0x46,0x27,0x18,0x89 }
	};
	bool fail = true;
	if (user[0] == target[1][3]) {
		if (user[1] == target[4][2]) {
			if (user[2] == target[5][5]) {
				if (user[3] == target[2][2]) {
					fail = false;
				}
			}
		}
	}
	if (fail) {
		kaboom();
	}
}
//ceaser cipher?
void phase_six(char *input) {
	size_t len = strlen(input);
	char *final_target = "awumbpqvokmiamzg";
	size_t target_len = strlen(final_target);
	if(len != target_len) {
		kaboom();
	}
	for (unsigned int i = 0; i < target_len; i++) {
		char target = input[i];
		if (97 <= target && target <= 122) {
			char base_lined = target - 97;
			char shifted = (base_lined + 8) % 26;
			char decrypted = shifted + 97;
			if(decrypted != final_target[i]){
				kaboom();
			}
		} else {
			kaboom();
		}
	}
	phase_defused();
}

void kaboom(void) {
	printf("KABOOM!!!!!11111ONE!!!!\r\n");
	exit(1);
}
