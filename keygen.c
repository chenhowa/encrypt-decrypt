/* Filename: keygen.c
 * Author: Howard Chen
 * Date: 8-9-2017
 * Description:
 * 	Creates a string of command-line specified length and outputs it to stdout.
 * 	The string will consist of the 27 allowable characters, and will be randomly
 * 	generated. The last character in the string, however, should be a newline character '\n'.
 *
 * 	All error text should be output to stderr, if any
 *
 * 	Usage: keygen <keyLength>
 * 		keygen 15 > my_key_file
 *
 */



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_CHAR 27

char int_to_char(int z);
int char_to_int(char c);



int main(int argc, char* argv[]) {
	int count;
	int c;
	char* key = NULL;
	int keylength;

	/* Seed random number generator */
	srand(time(NULL));	

	if(argc != 2) {
		perror("Incorrect arguments.\nUsage: ./keygen <keylength>\n");
		exit(1);
	}

	/*Ensure that the given keylength is valid. Note that atoi will convert strings
 * 	that have valid integer prefixes, like 20fd and 3abc, and simply convert the 
 * 	integer portion of the string and ignore the rest */
	keylength = atoi(argv[1]);
	if(keylength <= 0) {
		perror("Invalid keylength\n");
		exit(2);
	}

	/*Allocate space on the heap for the key */
	/*Leave space for null terminator and newline */
	key = malloc(keylength * sizeof(char) + 2 * sizeof(char) );
	if(key == NULL) {
		perror("Unexpected memory allocation error\n");
		exit(3);
	}

	/*Put the terminating characters (\0 and \n) in the string */
	memset(key, '\0', keylength * sizeof(char) + 2 * sizeof(char) );
	key[keylength] = '\n';

	/*Write exactly <keylength> characters to the key string */
	for(count = 0; count < keylength * sizeof(char); count++) {
		c = rand() % MAX_CHAR;
		key[count] = int_to_char(c);
	}
	
	/*At this point, all characters have been assigned to the key, including the 
 * 		'\n' character. So send the key string to stdout */
	printf("%s", key); fflush(stdout);

	return 0;
}

/* char_to_int: takes an uppercase letter character and converts it to an integer
 * args: [1] c: a char to be converted to the encoding int
 * pre: c should be an uppercase letter
 * ret: integer representing encoded char
 * post: returned value will be between 0 and 27, inclusive
 */
int char_to_int(char c) {
	int z;

	if (c == 32) { /*If c is the space character */
		z = MAX_CHAR - 1;
	} else {
		z = c - 65; /*65 is decimal for the 'A' character */ 
	}
	return z;
}

/* int_to_char: takes a positive integer and converts it to a capital letter character
 * args: [1] z: an integer to encode into an uppercase letter
 * pre: z should be between 0 and 27, inclusive. At the very least it should be non-negative.
 * ret: an uppercase letter reprsenting the encoded int
 * post: returned value will be an uppercase letter
 */
char int_to_char(int z) {
	char c;

	/*Ensure that z is in the correct range */
	z = z % MAX_CHAR;	
	if( z == MAX_CHAR - 1) {
		c = 32; /*32 is decimal for the ' ' character */
	} else {
		c = z + 65; /*65 is decimal for the 'A' character */	
	}

	return c;
}
