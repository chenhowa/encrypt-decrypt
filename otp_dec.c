/* Filename: otp_dec.c
 * Author: Howard Chen
 * Date: 8-9-2017
 * Description: A program that connects to otp_dec_d and asks it to send back an encrypted version
 * 		of a message.
 *
 * 		Usage: otp_dec <ciphertext> <key> <port>, where ciphertext is the file that contains
 * 		the ciphertext to be decrypted, key is the decryption key that will be used to decrypt
 * 		the text, and port is the port that otp_dec should try to connect to otp_dec_d on.
 */



#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h> /* for open and create functions*/
#include <unistd.h> /*for the close function */
#include <assert.h>
#include <dirent.h>

#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <signal.h>
int validate(int argc, char* argv[]);
int connect_to(char* hostname, char* portnum);
char* readFile(char* file_name, int* length);
int send_to(int socket, char* message);
char* receiveStream(int socket);
void error(const char *msg) { perror(msg); exit(0); } /* Error function used for reporting issues*/

int main(int argc, char* argv[]) {
	int valid;
	char* port;
	char* ciphertext_name;
	char* plaintext;
	char* ciphertext;
	char* key_name;
	char* key;
	char* status;

	int ciphertext_length = 0;
	int key_length = 0;

	int socket;

	/*First check that format of command line args is correct */
	valid = validate(argc, argv);
	if(valid == 0) {
		perror("Invalid command line arguments\n");
		exit(3);
	}


	/*Open the files for reading and check their length. Don't include the newline at the
 * 		end of the file */
	/*NOTE: ALL FILES USED HAVE TERMINATING NEWLINES */
	ciphertext_name = argv[1];
	ciphertext = readFile(ciphertext_name, &ciphertext_length);
	key_name = argv[2];
	key = readFile(key_name, &key_length);
	if(key_length < ciphertext_length) {
		fprintf(stderr, "Error: key '%s' is too short\n", key_name);
		exit(1);
	}

	/*Now that we know the command line arguments are valid, attempt to connect */
	port = argv[3];
	socket = connect_to("localhost", port);
	if(socket < 0) {
		/*Failure to connect */
		fprintf(stderr, "Error: could not contact otp_dec_d on port %s\n", port);	
		free(ciphertext);
		free(key);
		exit(2);
	}

	/*First verify identity with the daemon */
	send_to(socket, "otp_dec");
	send_to(socket, "@@@");
	sleep(1);

	status = receiveStream(socket);
	if( strcmp(status, "BAD") == 0) {
		fprintf(stderr, "Error: could not contact otp_dec_d on port %s\n", port);	
		free(status);
		free(ciphertext);
		free(key);
		close(socket);
		exit(2);
	}

	

	/*Now that we have VERIFIED connection to the daemon, send the files over to
 * 		the daemon for encryption */
	send_to(socket, ciphertext); 
	send_to(socket, "@@@");
	sleep(1);
	
	send_to(socket, key);
	send_to(socket, "@@@");
	sleep(1);

	plaintext = receiveStream(socket);
	printf("%s\n", plaintext);

	/*Clean up resources: heap and sockets */
	free(ciphertext);
	free(plaintext);
	free(key);
	free(status);
	close(socket);

	return 0;
}

/* receiveStream: receives bytes from a socket
 * args: [1] socket representing TCP socket connected to another tcp socket
 * pre: socket should already be connected. A single stream is ended by the ending
 * 	sequence "@@@" that is sent by the sender
 * ret: char* to dynamically allocated memory holding the received message
 * post: the stream does not include the "@@@" terminating sequence
 	Caller will need to free returned string */
char* receiveStream(int socket) {
	char* buffer = NULL;
	char* start = NULL;
	int bytesRead = 0;
	int totalBytes = 0;
	int bufferlen = 1024;

	int index;

	buffer = malloc(bufferlen * sizeof(char));
	start = buffer;
	memset(start, '\0', bufferlen);
	while( totalBytes < bufferlen) {
		/*Put start at the next available space */
		start = buffer + totalBytes;
		
		/*Read memory until 3 null terminators left */
		bytesRead = recv(socket, start, bufferlen - totalBytes - 5, 0);
		totalBytes = totalBytes + bytesRead;

		/*If the terminating characters are received, we are done */
		if(strstr(start, "@@@") != NULL ){
			break;

		}

		/*If over half the buffer has been used, reallocate memory */
		if(totalBytes > (bufferlen / 2)  ) {
			bufferlen = bufferlen * 2;
			buffer = realloc(buffer, bufferlen);

			/*Null terminate the rest of the string */
			start = buffer + totalBytes;
			memset(start, '\0', bufferlen - totalBytes - 2); /*Off by one error? */
		}
	}	

	/*Now that we've read all the bytes for this stream,
 * 		strip off null terminator and return pointer to the result */
	start = strstr(start, "@@@");
	for(index = 0; index < 3; index++) {
		start[index] = '\0';
	}
	return buffer;
}


/* send_to: function for sending an entire string into a socket
 * args: [1] socket: a file descriptor to an opened tcp connection
 * 	[2] message: string to send through the socket
 * pre: socket should be valid and opened
 * ret: int: -1 if error occured; 0 otherwise
 * post: entire message will have been sent into socket  
 *
 *  	Citation: Borrowed largely from Beej's guide */
int send_to(int socket, char* message) {
	/*FOR ALL RECEIVING FUNCTIONS, NEED TO STRIP OFF THE TERMINATING SPACES
 * 		AND TERMINATING @@@ code!!! */
	/*REALLY IMPORTANT<<< THE TERMINATORS ARE NOT PART OF THE MESSAGE */
	int total = 0;
	int bytesleft;
	int length;
	int n;

	length = strlen(message);
	bytesleft = length;

	/*While the total number of bytes sent is not the length of the message
 * 		keep sending the remaining bytes */
	while(total < length) {
		n = send(socket, message + total, bytesleft, 0);
		if( n == -1) { break; } /* -1 is returned if an error occurred*/
		total += n;
		bytesleft -= n;
	}

	if( n == -1) { perror("Problem sending\n"); return -1; }
	else { return 0; }
}

/* readFile: reads in a text file and keeps track of its length (not including terminating newline)
 * args: [1] file_name: name of the file to open for reading
 * 	[2] length: pointer to an int to store the length of the file
 * pre: file should exist in the current direcotry.
 * 	file should only contain capital letters and spaces, and possibly a newline
 * 		at the very end of the file
 * ret: pointer to a char* representing the string allocated to hold the file characters
 * post: caller must free the returned string
 */
char* readFile(char* file_name, int* length) {
	FILE* fp;
	char c;
	char* buffer = NULL;
	int bufferlen;

	fp = fopen(file_name, "r");
	if(fp == NULL) {
		perror("File name not found. Terminating\n");
		exit(1);
	}

	/*If file was opened successfully, read in one char at a time and validate
 * 		it before putting it in the allocated array. Reallocate the array as
 * 		necessary */
	bufferlen = 1024;
	buffer = malloc(sizeof(char) * bufferlen);
	*length = 0;
	c = getc(fp);
	while( (c != EOF) && (c != '\n') ) {
		/*Check that c is either space or an uppercase ASCII letter */
		if(c != 32 && !(c >= 65) && !(c <= 90) ) {
			perror("otp_dec error: input contains bad characters\n");
			exit(1);
		}

		/*Otherwise, check size of buffer and determine if it needs to be reallocated */
		if(*length > (bufferlen - 20) ) {
			bufferlen = bufferlen * 2;
			buffer = realloc(buffer, sizeof(char) * bufferlen);
			if(buffer == NULL) {
				perror("Error in memory allocation\n");
				exit(3);
			}

		}

		/*If there's enough space, store the char */
		buffer[*length] = c;
		(*length)++;
		c = getc(fp);
	}

	/*Pad the rest of the buffer with null terminators */
	/*Leave a margin for error */
	memset( buffer + (*length), '\0', bufferlen - (*length) - 5);

	/*At the end of this, we've read all the file's characters. Remove the newline
 * 	close the file, and return a pointer to the allocated string */
	if(buffer[(*length) - 1] == '\n') {
		buffer[(*length) - 1] = '\0';
		(*length)--;
	}
	fclose(fp);

	return buffer;
}

/* Description: connects to a host at a given port number
 * args: [1] hostname: name of the host
 *	[2] portnum: port number host is listening on
 * pre: to connect successfully, host must be listening on the port
 * ret: int: either a file descriptor to a new socket for a new connection
 * 	to the host, or a negative integer, indicating an error occured
 * post: socket was opened. Caller will need to close it
 * 	
 * 	Citation: from the provided client.c file 
 */
int connect_to(char* hostname, char* portnum) {

	int socketFD, portNumber;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;

	/* Set up the server address struct*/
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); /* Clear out the address struct*/
	portNumber = atoi(portnum); /* Get the port number, convert to an integer from a string*/
	serverAddress.sin_family = AF_INET; /* Create a network-capable socket*/
	serverAddress.sin_port = htons(portNumber); /* Store the port number*/
	serverHostInfo = gethostbyname(hostname); /* Convert the machine name into a special form of address*/
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(0); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); /* Copy in the address*/
	/* Set up the socket*/
	socketFD = socket(AF_INET, SOCK_STREAM, 0); /* Create the socket*/
	if (socketFD < 0) error("CLIENT: ERROR opening socket");

	/* Connect to server*/
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) /* Connect socket to address*/
		error("CLIENT: ERROR connecting");

	return socketFD;
}

/*Attempt to validate the command line parameters */
/*Checks that there are 4 total command line parameters, an that the 4th one
 * can be converted to an integer. Returns 0 if it discovers the above
 * conditions do not hold; otherwise returns 1 */
int validate(int argc, char* argv[]) {
	/*First, check that the command lines are correct */
	if(argc != 4) {
		perror("Incorrect number of arguments. Need 3\n");
		return 0;
	}

	/*Next, check that the port number can actually be parsed as an int */
	if(atoi(argv[3]) == 0) {
		return 0;
	}
	return 1;
}
