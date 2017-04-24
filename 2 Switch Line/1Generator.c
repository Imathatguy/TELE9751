/* Daniel Paul Iuliano
z3101121
diuliano@gmail.com
Thesis Topic University of New South Wales
Supervisor: Tim Moors
The PC Switch

Packet Control
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>		// socket() & bind()
#include <errno.h>			// DieWithError() function
#include <arpa/inet.h>		// sockaddr_in
#include <time.h>			// for random time seed

#define OUTPUT_PORT 50000
#define LOCAL_ADDRESS "127.0.0.1"
#define MAX_MSG_LEN 200

/* Packet Struct layout
[destination address][source address][length of data][DATA everything from IP stuff to TCP to whatever][Frame Check Sequence]
[(6 bytes)          ][(6bytes)      ][(2bytes)      ][DATA(maybe some padding)                        ][(4bytes)            ]
[6 unsigned chars   ][6unsignedchars][short int     ][DATA                                            ][int                 ]
18 compulsory bytes in official packet type

in our packet type, since addresses are stored as binary string of chars, each address entry is larger
[dest addr (32bytes)][source addr (32bytes)][dataLength (2bytes)][DATA (random length but for our purposes, fixed to 100bytes)][FCS (4bytes)][fromPort (2bytes)][toPort (2bytes)]
*/
typedef struct packet packet;
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

// prototypes for functions
int checkIP(int i1, int i2, int i3, int i4);
void createIP(int i1, int i2, int i3, int i4, char ip_addr[4][9]);
packet createPacket(int lastSent, int txtSend);
void DieWithError(char *errorMessage);
void dec2bin(int decimal, char *binary, int length);
int bin2dec(char *binary);
void error(char *);
void wait (int randTime);
void sleep(unsigned int mseconds);

int dtxt[4], stxt[4], sizetxt, porttxt;	// variables to store data from txt file	

int main(void) {
	struct sockaddr_in genOUT_addr;
	int sockOUT, n=300, lastSent=0, txtSend, x;	// n is how many packets per sequence to send
	packet outGoing;
	FILE *file;
	
	//------------------Network code--------------	
	// Open sockets
	if((sockOUT = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		DieWithError("socket() failed");
		
	// Construct address structure
	bzero((char *)&genOUT_addr,sizeof(genOUT_addr));		// zeroes out struct before data copied
    genOUT_addr.sin_family = AF_INET;						// specifies Address Family
    genOUT_addr.sin_addr.s_addr = inet_addr(LOCAL_ADDRESS);	// Connect to local address
    genOUT_addr.sin_port = htons(OUTPUT_PORT);				// output port assigned to struct
    //--------------End Network code--------------
    
    srand (time(NULL));		// initialize random seed
    
    file = fopen("genStream.txt", "r");
	if(file != NULL) {
		fscanf(file, "Destination:%i.%i.%i.%i Source:%i.%i.%i.%i Port:%i Size:%i", &dtxt[0], &dtxt[1], &dtxt[2], &dtxt[3], &stxt[0], &stxt[1], &stxt[2], &stxt[3], &porttxt, &sizetxt);
		fclose(file);
	}
	
	printf("Destination:%i.%i.%i.%i Source:%i.%i.%i.%i Port:%i Size:%i\n", dtxt[0], dtxt[1], dtxt[2], dtxt[3], stxt[0], stxt[1], stxt[2], stxt[3], porttxt, sizetxt);
    x = n;	// variable assigned to n before it changes to keep track of initial amount of packets to be sent
		 
	while(n>0) {
		txtSend = n % 2;	// txtPacket is 0 on even packets, so createPacket() creates txt packet
		
		outGoing = createPacket(lastSent, txtSend);	// creates random packet or packet from txt file
		outGoing.sequenceNum = ((x + 1) - n);		// inserts sequence number
				
		if(sendto(sockOUT, &outGoing, MAX_MSG_LEN, 0, (struct sockaddr *)&genOUT_addr, sizeof(genOUT_addr)) != MAX_MSG_LEN)
			DieWithError("sendto() failed");
		printf("Packet %i enters switch on port %i at time %i\n", outGoing.sequenceNum, outGoing.fromPort, outGoing.timer);
		
		lastSent = outGoing.timer;
		
		n--;
	}
	
	return 1;
}


/*	************************
	PACKET CONTROL FUNCTIONS
	************************ */
	
packet createPacket(int lastSent, int txtSend) {
	int dest[4], src[4], packetSize, n, sameTime;
	char ip_dest[4][9], ip_source[4][9];
	packet newPacket;
	
	// creating random number for source/dest address
	if(txtSend == 0) {
		for(n=0;n<4;n++) {
			dest[n] = dtxt[n];
			src[n] = stxt[n];
		}
		packetSize = sizetxt;
		newPacket.fromPort = porttxt;
	} else {
		for(n=0;n<4;n++) {
			dest[n] = rand() % 256;
			src[n] = rand() % 256;
		}
		packetSize = rand() % 99;
		newPacket.fromPort = rand() % 8;
	}
	/*d1 = rand() % 256;		// generate random number
	d2 = rand() % 256;
	d3 = rand() % 256;
	d4 = rand() % 256;
	s1 = rand() % 256;
	s2 = rand() % 256;
	s3 = rand() % 256;
	s4 = rand() % 256;*/
	
	createIP(dest[0], dest[1], dest[2], dest[3], ip_dest);
	createIP(src[0], src[1], src[2], src[3], ip_source);

	for(n=0;n<4;n++)
		strcpy(newPacket.ip_dest[n], ip_dest[n]);
	for(n=0;n<4;n++)
		strcpy(newPacket.ip_source[n], ip_source[n]);
		
	// create random string for data to give packets random sizes
	
	for(n=0;n<packetSize;n++)
		newPacket.data[n] = 'a';
	newPacket.data[n] = '\0';
	newPacket.dataLength = strlen(newPacket.data);
	
	newPacket.frameCheck = 4;
	
	// create random timer for each packet with certain % having same time
	sameTime = rand() % 10;
	
	if(sameTime < 1)	// 5% chance of same time
		newPacket.timer = lastSent;
	else {
		newPacket.timer = lastSent + sameTime;	
	}
		
	return newPacket;
}

/*	**************
	MISC FUNCTIONS
	************** */

void error(char *msg)
{
	perror(msg);
	exit(0);
}

// Checks syntax of IP address and return "cont" flag
int checkIP(int i1, int i2, int i3, int i4) {
	int cont=0;
	if((i1>=0 && i1<=255) && (i2>=0 && i2<=255) && (i3>=0 && i3<=255) && (i4>=0 && i4<=255))
		cont=1;
	else
		printf("Incorrect IP syntax.\n");
	return cont;
}

// Merge 4 numbers into multi-dimensional array
void createIP(int i1, int i2, int i3, int i4, char ip_addr[4][9]) {
	// Zero the ip address
	int n,i;
	for(i=0;i<4;i++) {
		for(n=0;n<8;n++) {
			ip_addr[i][n] = '0';
		}
	}
	// Convert each number of the IP address to binary conversion (8bits)
	dec2bin(i1, ip_addr[0], 8);
	ip_addr[0][8] = '\0';
	dec2bin(i2, ip_addr[1], 8);
	ip_addr[1][8] = '\0';
	dec2bin(i3, ip_addr[2], 8);
	ip_addr[2][8] = '\0';
	dec2bin(i4, ip_addr[3], 8);
	ip_addr[3][8] = '\0';
}

// dec2bin conversion from decimal to binary used&edited from: http://www.daniweb.com/code/snippet87.html
void dec2bin(int decimal, char *binary, int length) {
	int k = 0, n, i, remain;
	char temp[length];
	// zero the binary string
	for(n=0;n<=length;n++) {
		binary[n] = '0';
	}
	
	do {
		remain = decimal % 2;
		// whittle down the decimal number
		decimal = decimal / 2;
		// converts digit 0 or 1 to character '0' or '1'
		temp[k] = remain + '0';
		k++;
	} while (decimal > 0);
	
	// reverse the spelling
	n=length-1;
	for(i=0;i<k;i++) {
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

void wait (int randTime) { // borrowed and edited from http://www.cplusplus.com/reference/clibrary/ctime/clock.html
  	clock_t endwait;
  	int clocks_per_time;
  	
  	//srand (time(NULL));						// initialize random seed
	clocks_per_time = rand() % 1000;		// generate random
		
  	endwait = clock () + randTime * clocks_per_time;
  	while (clock() < endwait) {}
}

void sleep(unsigned int mseconds) {
    clock_t goal = mseconds + clock();
    while (goal > clock());
}
