/* Daniel Paul Iuliano
z3101121
diuliano@gmail.com
Thesis Topic University of New South Wales
Supervisor: Tim Moors
The PC Switch

8 port Banyan switching Fabric
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>			// for ceil() function
#include <sys/socket.h>		// socket() & bind()
#include <errno.h>			// for DieWithError() function
#include <arpa/inet.h>		// sockaddr_in

#define INPUT_PORT 50014
#define OUTPUT_PORT 50015
#define LOCAL_ADDRESS "127.0.0.1"
#define MAX_MSG_LEN 200

// create banyan fabric struct
typedef struct banyanElement banyanElement;
struct banyanElement {
	int elementNumber;
	int topFlag;
	int bottomFlag;
	banyanElement *zero;
	banyanElement *one;
};
banyanElement *elements[12];
banyanElement *nextElement = NULL;

typedef struct packet packet; // packet struct
struct packet {
	char ip_dest[4][9];
	char ip_source[4][9];
	short int dataLength;
	char data[100];
	int frameCheck;
	int fromPort;
	int toPort;
	int sequenceNum;
	int portSequenceNum;
	int timer;
};

// Fabric functions
int banyan(char *out_addr, banyanElement *currentElement);
int checkPos(int current);
void fabricElements();

// Misc Functions
void dec2bin(int decimal, char *binary, int length);
int bin2dec(char *binary);
void DieWithError(char *errorMessage);

int main(void) {
	struct sockaddr_in clasOUT_addr;	// client info (classifier) variable, data given when received message
	struct sockaddr_in fabIN_addr;		// struct for incoming packets
	struct sockaddr_in fabOUT_addr;		// struct for outgoing packets
	unsigned int clasAddrLen;			// int to store length of client address (classifier) data when received
	packet recvPacket;					// packet struct that will be received
	int n, start, sockIN, sockOUT, recvMsgLen, port, timer=100, count; //timer is 101 because first packet has to be between 0 and 99
	char output[4], input[4];
	
	//----------------Network code----------------
	// Open socket
	if((sockIN = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		DieWithError("socket() failed");
	if((sockOUT = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		DieWithError("socket() failed");
	
	// Construct local address structure
	bzero((char *)&fabIN_addr, sizeof(fabIN_addr));	// zeroes out struct before data copied
    fabIN_addr.sin_family = AF_INET;				// specifies Address Family
    fabIN_addr.sin_addr.s_addr = htonl(INADDR_ANY);	// accept from any network interface
    fabIN_addr.sin_port = htons(INPUT_PORT);		// Using port 5001
    // Construct outgoing address structure
	bzero((char *)&fabOUT_addr,sizeof(fabOUT_addr));			// zeroes out struct before data copied
    fabOUT_addr.sin_family = AF_INET;							// specifies Address Family
    fabOUT_addr.sin_addr.s_addr = inet_addr(LOCAL_ADDRESS);		// Connect to local address
    fabOUT_addr.sin_port = htons(OUTPUT_PORT);					// output port 5002
	
    // Binding above data (address/port/etc) to socket descriptor sock for port 5001
    if((bind(sockIN, (struct sockaddr *)&fabIN_addr, sizeof(fabIN_addr))) < 0)
    	DieWithError("bind() failed");
    //--------------End Network code--------------

    fabricElements();
    	
	while(1) {
		if((recvMsgLen = recvfrom(sockIN, (void*)&recvPacket, MAX_MSG_LEN, 0, (struct sockaddr *) &clasOUT_addr, &clasAddrLen)) < 0)
    		DieWithError("recvfrom() failed");

		// if timestamp on this packet is different from previous packet, then reset flags on elements
		if(recvPacket.timer != timer) {
			for(count=0;count<12;count++) {
				elements[count] -> topFlag = 0;
				elements[count] -> bottomFlag = 0;
			}
			timer = recvPacket.timer;
		}

		// Convert output/input ports to binary strings
		dec2bin((recvPacket.toPort), output, 3); 	// destination port (from classifier)
		dec2bin((recvPacket.fromPort), input, 3);	// port packet was received on (from generator)
			
		// determine starting element by taking all but last bit of input port#
		// which gives you starting element
		// i.e. starting at port 101 (5), take first two 10=0, so start at element 2
		n=strlen(input);
		n--;
		input[n]='\0';
		start = bin2dec(input);

		port = banyan(output, elements[start]);
		
		if(port == 10)
			printf("Packet %i dropped.\n", recvPacket.sequenceNum);
		else {
			recvPacket.fromPort = port;		// from banyan function
			recvPacket.toPort = port;		// from banyan function
					
			// need to send packet to packetScheduler and change the fromPort field to appropriate port
			if(sendto(sockOUT, &recvPacket, MAX_MSG_LEN, 0, (struct sockaddr *)&fabOUT_addr, sizeof(fabOUT_addr)) != MAX_MSG_LEN)
				DieWithError("sendto() failed");
		}
	}
	
	return 0;
}

/*
BANYAN FUNCTIONS
*/

void fabricElements() {
	int n=0;
	while(n<12) {
		if((elements[n] = (banyanElement *)malloc(sizeof(banyanElement))) != NULL){
			elements[n] -> elementNumber = n;
			elements[n] -> topFlag = 0;
			elements[n] -> bottomFlag = 0;
		} else {
			printf("Out of Memory");
			exit(0);
		}
		n++;
	}
	
	elements[0]->zero = elements[4];
	elements[0]->one  = elements[6];
	elements[1]->zero = elements[5];
	elements[1]->one  = elements[7];
	elements[2]->zero = elements[4];
	elements[2]->one  = elements[6];
	elements[3]->zero = elements[5];
	elements[3]->one  = elements[7];
	
	elements[4]->zero = elements[8];
	elements[4]->one  = elements[9];
	elements[5]->zero = elements[8];
	elements[5]->one  = elements[9];
	elements[6]->zero = elements[10];
	elements[6]->one  = elements[11];
	elements[7]->zero = elements[10];
	elements[7]->one  = elements[11];
	
	/* Will print out graphical representation of Banyan (optional)
	printf("        ___     ___     ___        \n");
	printf("000 ---| 0 |---| 4 |---| 8 |--- 000\n");		
	printf("001 ---|___|   |___|\\  |___|--- 001\n");
	printf("           \\    /    \\/            \n");
	printf("        ___ \\  /___  /\\ ___        \n");
	printf("010 ---| 1 |---| 5 |/  | 9 |--- 010\n");		
	printf("011 ---|___| /\\|___|---|___|--- 011\n");
	printf("           \\/  \\/                  \n");
	printf("        ___/\\  /\\__     ___        \n");
	printf("100 ---| 2 | \\/| 6 |---| 10|--- 100\n");		
	printf("101 ---|___|---|___|\\  |___|--- 101\n");
	printf("            /  \\     \\/            \n");
	printf("        ___/   _\\__  /\\ ___        \n");
	printf("110 ---| 3 |   | 7 |/  | 11|--- 110\n");		
	printf("111 ---|___|---|___|---|___|--- 111\n");
	*/
}

int banyan(char *out_addr, banyanElement *currentElement) {
	int stage, stageElements=4, port, blocked=0;
	// if element number is between 0 and 3, check addressPosition 0 [stage = 0]
	// if between 4 and 7, check addressPosition 1 [stage = 1]
	// if between 8 and 11, check addressPosition 2 [stage = 2]
	
	// takes upper limit of [elementNumber devided by how many elements in a column]
	// this works for any number of elements as there always has to be same amount 
	// of elements per column and only powers of 2 ports
	stage = ceil (currentElement->elementNumber / stageElements);	/* [e / (n/2)] */

	if(out_addr[stage] == '0') {	// send from top node of element
		// check whether output zero has been used, if not allow this packet to go through & record that it has been used; else discard this packet
		if(currentElement -> topFlag == 0) {
			nextElement = currentElement->zero;
			currentElement -> topFlag = 1;
		} else {	// element node busy, packed dropped. blocked flag changed to 1
			blocked = 1;
		}
	} else {		// send from bottom node of element
		if(currentElement -> bottomFlag == 0) {
			nextElement = currentElement->one;
		} else {	// element node busy, packed dropped. blocked flag changed to 1
			blocked = 1;
		}
	}

	if(blocked)
		return 10;
	
	if(nextElement == NULL) {
		return bin2dec(out_addr);
	}
	
	port = banyan(out_addr, nextElement);
	
	return port;
}

/*
MISC FUNCTIONS
*/

// dec2bin conversion from decimal to binary used&edited from: http://www.daniweb.com/code/snippet87.html
void dec2bin(int decimal, char *binary, int length) {
	int k = 0, n, i, remain;
	char temp[length];

	for(n=0;n<length;n++) {		// zero the binary string
		binary[n] = '0';
	}
	binary[n] = '\0';
	
	do {
		remain = decimal % 2;	// whittle down the decimal number
		decimal = decimal / 2;
		temp[k] = remain + '0';	// converts digit 0 or 1 to character '0' or '1'
		k++;
	} while (decimal > 0);
	
	n=length-1;
	for(i=0;i<k;i++) {			// reverse the input
		binary[n] = temp[i];
		n--;
	}
}

// Convert binary string into decimal
int bin2dec(char *binary) {
	int n=strlen(binary)-1, i=1, decimal=0;
	
	while(n>=0) {
		if(binary[n] == '1')
			decimal = decimal+i;
		n--;
		i = i*2;
	}
	
	return decimal;
}

void DieWithError(char *errorMessage)
{
    perror(errorMessage);
    exit(1);
}
