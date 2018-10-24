#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include "serial.h"

void valid_serial_one(char *serial){
	size_t length = strlen(serial);
	if(length <= 40 || length > 60) {
		reject();
	}
}

void valid_serial_two(char *serial){
	size_t length = strlen(serial);
	if(length <= 40 || length > 60) {
		reject();
	}

	for(unsigned int i = 0; i < length; i++) {
		if(serial[i] < 'a'|| serial[i] > 'z'){
			reject();
		}
	}
}

void valid_serial_three(char *serial){
	size_t length = strlen(serial);
	if(length <= 40 || length > 60) {
		reject();
	}

	for(unsigned int i = 0; i < length; i++) {
		if(serial[i] < 'a'|| serial[i] > 'z'){
			reject();
		}
	}

	unsigned long long count = 0;
	for(unsigned int i = 0; i < length; i++) {
		count+= serial[i];
	}
	if(count != 'n' * 40) {
		reject();
	}
}

void valid_serial_four(char *serial){
	size_t length = strlen(serial);
	if(length <= 40 || length > 60) {
		reject();
	}

	for(unsigned int i = 0; i < length; i++) {
		if(i % 5 == 0 && i > 0){
			if(serial[i] != '-') reject();
		} else {
			if(serial[i] < 'a' || serial[i] > 'z'){
				reject();
			}
		}

	}

	unsigned long long count = 0;
	for(unsigned int i = 0; i < length; i++) {
		count += serial[i];
	}
	if(count != 'n' * 40) {
		reject();
	}
}

void valid_serial_combo(char *serial_one, char *serial_two){
	char *check_one = "mwr_labs";
	size_t len_check_one = strlen(check_one);
	char *check_two = "hack.lu";
	size_t len_check_two = strlen(check_two);

	if(strlen(serial_one) != len_check_one || strlen(serial_two) != len_check_two){
		reject();
	}

	for(unsigned int i = 0; i < len_check_one; i++){
		if(serial_one[i] != check_one[i]){
			reject();
		}
	}
	for(unsigned int i = 0; i < len_check_two; i++){
		if(serial_two[i] != check_two[i]){
			reject();
		}
	}
}

void reject(void) {
	exit(1);
}
