/* Filename: otp_dec.c
 * Author: Howard Chen
 * Date: 8-9-2017
 * Description: Behavior is almost identical to otp_enc_d, in syntax and usage,
 * 	except it is connected to by otp_dec, and otp_dec sends it a ciphertext file and a key, 
 * 	and otp_dec_d will send back the original plaintext.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>

#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <signal.h>

#define MAX_PROC 5
#define MAX_CHAR 27

int char_to_int(char c);
void quick_cleanup(int *process_count);
int send_to(int socket, char* message);
char int_to_char(int z);
char* decrypt(char* data, char* key);
void receiveMessage(int socket, char name[], int max);
char* receiveStream(int socket);
void block_cleanup(int *process_count);
void process(int client);
int validate(int argc, char* argv[]);
int listen_on(char* port);
void error(const char *msg); 
int accept_connection( int listenSocketFD);

int main(int argc, char* argv[]) {
	int valid;
	char* port;
	int server;
	int client;
	int process_count = 0;	

	process_count = 0;
	valid = validate(argc, argv);
	if(valid == 0) {
		perror("Incorrect number of arguments\n");
		exit(1);
	}

	port = argv[1];
	server = listen_on(port);
	if(server < 0) {
		perror("Failed to listen on port\n");
		exit(1);
	}

	while(1) {
		if(process_count < MAX_PROC) {
			/*If there's room, accept a new connection */
			client = accept_connection(server);
			process_count++;

			/*Take the socket, and start a child process to handle getting
 * 				ciphertext, decrypting it, sending back the plaintext, and
 * 				closing the socket */
			process(client);
		}
		else { /*If the process limit is reached, block until you can
				clean up at least 1  process */
			block_cleanup(&process_count);

		}
		/*No matter what, check briefly if any processes are waiting to be cleaned up */
		quick_cleanup(&process_count);
	}

	return 0;
}

/* Process: forks off a child process to receive bytes from a socket, decrypt them
 * 		and send them back to otp_dec
 * args: [1] socket: open socket file descriptor
 * pre: socket should be opened, and shoudl either be communicating with otp_enc or otp_dec
 * ret: none
 * post: decrypted bytes will be sent back to otp_dec, or if the other process is otp_enc
 * 	otp_enc will be informed that it has been rejected
 */
void process(int socket) {
	pid_t spawnpid = -5;
	char* ciphertext;
	char* plaintext;
	char* key;
	char *name;

	/*Spawn a new process to get ciphertext, do decryption, and send back plaintext */
	spawnpid = fork();

	switch (spawnpid) {
		case -1:
			perror("Failure to spawn a process!\n"); fflush(stderr);
			exit(1);
			break;
		case 0:
			/*In child process: */
			name = receiveStream(socket);

			/*If other  process is not otp_dec, reject it */
			if(strstr(name, "otp_dec") == NULL) {
				send_to(socket, "BAD");
				send_to(socket, "@@@");
				sleep(1);
				close(socket);
				exit(1);
			}
			else {
				/*Otherwise tell client it is okay to proceed*/
				send_to(socket, "GOOD");
				send_to(socket, "@@@");
				sleep(1);
			}

			/*If the other process was otp_dec, get ciphertext and key*/
			ciphertext = receiveStream(socket);
			key = receiveStream(socket);	

			/*Decrypt ciphertext and send to client */
			plaintext = decrypt(ciphertext, key);
			send_to(socket, plaintext);
			send_to(socket, "@@@");
			sleep(1);
			
			/*Done with the decryption, so end close the communication socket and
 * 				end the child process */
			free(plaintext);
			free(key);
			free(ciphertext);
			free(name);
			close(socket);
			exit(0);
			break;
		default:
			/*In parent process: */

			/*Do nothing just go back and either accept more or cleanup */		
			break;
	}

	/*As parent, simply return */
	return;
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

	if( n == -1) { return -1; }
	else { return 0; }
}

/* decrypt: decrypts a string using a key
 * args: [1] data: string to be decrypted
 * 	[2] key: string to use for decryption
 * pre: key must be at least as long as the data
 * 	key and data should only contain uppercase letters and spaces
 * ret: decrypted string, allocated on heap
 * post: caller must free returned string
 * 	To encrypt, use the encrypt() function
 */
char* decrypt(char* data, char* key) {
	char* plaintext = NULL;
	int datalen;
	int index;

	int data_code;
	int key_code;
	int plain_code;

	datalen = strlen(data);	
	/*Doublecheck that the key is at least as long as the data */
	assert( datalen <= strlen(key) );

	/*If so, for each character in data, decrypt it */
	plaintext = malloc( sizeof(char) * datalen + 1); 
	memset(plaintext, '\0', sizeof(char) * datalen + 1);

	for(index = 0; index < datalen; index++) {
		/*Generate the plain_code */
		data_code = char_to_int(data[index]);
		key_code = char_to_int(key[index]);
		plain_code = (data_code - key_code);
		if(plain_code < 0) {plain_code += MAX_CHAR; }

		/*Save the plaincode as a char */
		plaintext[index] = int_to_char(plain_code);
	}

	/*At this point, the entire plaintext has been generated
 * 		and stored in the heap, so return a pointer to it */
	return plaintext;
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

/* I didn't use this (I think), and in the future I will delete this */
void receiveMessage(int socket, char name[], int max) {
	char* start = name;
	int totalBytes = 0;
	int bytesRead = 0;
	int index;

	memset(name, '\0', sizeof(name));
	while(totalBytes < max - 2) {
		start = start + totalBytes;
		bytesRead = recv(socket, start, max - totalBytes, 0); 	

		totalBytes = totalBytes + bytesRead;

		if(strstr(name, "@@@") != NULL) {
			break;
		}
	}
	/*At this point, the entire command list should have been read */
	/*Get rid of the terminator and return */
	start = strstr(start, "@@@");
	for(index = 0; index < 3; index++) {
		start[index] = '\0';
	}

	return;
}

/* Description: checks for background processes that have terminated, and cleans up any
 * 		that are zombies that are discovred. Does not block
 * args: none
 * pre: none
 * post: any zombie child processes currently available will be cleaned up
 * ret: none
 */
void quick_cleanup(int *process_count) {
	int childPID = 5;
	int childExitMethod = 5;

	/*Clean up every terminated background process that is currently available*/
	/*Don't block */
	childPID = waitpid(-1, &childExitMethod, WNOHANG);
	while(childPID != 0 && childPID != -1) {
		if(*process_count > 0) { (*process_count)--; }
		
		/*Check if any more background processes can be cleaned up */
		childPID = waitpid(-1, &childExitMethod, WNOHANG);
	}
	return;
}

/* Description: cleans up at least one child process, by blocking
 * args: [1] process_count: pointer to an int that holds the number of child processes
 * pre: process_count > 0, which means at least 1 child process exists to be cleand up.
 * 	otherwise this function will block forever
 * ret: none
 * post: process_count will be decreased
 */
void block_cleanup(int *process_count) {
	int exitMethod;
	int childPID;

	while( !(wait(&exitMethod) > 0)  ){
		/*Wait until at least one child is cleaned up */	
	}
	if (*process_count > 0) { (*process_count)--; }

	/*Check  if there are any more that need to be cleaned up */
	childPID = waitpid(-1, &exitMethod, WNOHANG);
	while(childPID != 0 && childPID != -1) {
		if(*process_count > 0) {(*process_count)--; }

		/*Check if any more background processes can be cleaned up */
		childPID = waitpid(-1, &exitMethod, WNOHANG);
	}
}


/* Description: uses a listening socket to accept a new connection, and returns the new socket
 * args: [1] listenSocketFD: a file descriptor to a socket that is listening on some localhost port
 * pre: listenSocketFD is a listening socket
 * ret: a file descriptor to a new socket from a newly accepted client connection
 * post: returned file descriptor must be closed by the caller at some point
 *
 * citation: from provided server.c file
 */
int accept_connection( int listenSocketFD)  {
	int establishedConnectionFD; 
	socklen_t sizeOfClientInfo;
	struct sockaddr_in clientAddress;

	/* Accept a connection, blocking if one is not available until one connects*/
	sizeOfClientInfo = sizeof(clientAddress); /* Get the size of the address for the client that will connect*/
	establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); /* Accept*/
	if (establishedConnectionFD < 0) { error("ERROR on accept"); } /*This error on accept should never happen */

	return establishedConnectionFD;
}

/* Description: Returns a file descriptor to a socket that is listening on the specified port number
 * Arguments: [1] port: string representation of the port number to listen on
 * Pre: None
 * Ret: a file descriptor to a socket
 * Post: The file descriptor is open and listening, and will have to be closed by the caller
 * 
 * citation: from provided server.c file
 */
int listen_on(char* port) {
	int listenSocketFD; 
	struct sockaddr_in serverAddress;
	int portNumber;

	portNumber = atoi(port); /* Get the port number, convert to an integer from a string*/
	/*Error check the port number */
	if( portNumber == 0) {
		error("Invalid port number\n");
	}

	/* Set up the address struct for this process (the server)*/
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); /* Clear out the address struct*/
	serverAddress.sin_family = AF_INET; /* Create a network-capable socket*/
	serverAddress.sin_port = htons(portNumber); /* Store the port number*/
	serverAddress.sin_addr.s_addr = INADDR_ANY; /* Any address is allowed for connection to this process*/


	/* Set up the socket*/
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); /* Create the socket*/
	if (listenSocketFD < 0) { error("ERROR opening socket"); }


	/* Enable the socket to begin listening*/
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) /* Connect socket to port*/
	{	error("ERROR on binding");}
	listen(listenSocketFD, 10); /* Flip the socket on - it can now receive up to 5 connections*/

	/*Return a file descriptor to the listening socket */
	return listenSocketFD;
}

/*Attempt to validate the command line parameters */
/*Checks that there are 2 total command line parameters, an that the 2nd one
 * can be converted to an integer. Returns 0 if it discovers the above
 * conditions do not hold; otherwise returns 1 */
int validate(int argc, char* argv[]) {
	if(argc != 2) {
		return 0;
	}
	/*Check that the second argument can be casted as an integer */
	if(atoi(argv[1]) == 0) {
		return 0;
	}
	return 1;
}

void error(const char *msg) { perror(msg); exit(1); } /* Error function used for reporting issues*/
