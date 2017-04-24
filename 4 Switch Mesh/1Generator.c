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
#define OUTPUT_PORT2 50010
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

// Generator functions
void createIP(int i1, int i2, int i3, int i4, char ip_addr[4][9]);
packet createPacket(int lastSent, int txtSend);

// Misc functions
void DieWithError(char *errorMessage);
void dec2bin(int decimal, char *binary, int length);
int bin2dec(char *binary);

int dtxt[4], stxt[4], sizetxt, porttxt=9;	// variables to store data from txt file	

int main(void) {
	struct sockaddr_in genOUT_addr;
	struct sockaddr_in genOUT2_addr;
	// totalPacket variable controls how many packets sent per session (max 300)
	// variation is amount of packets per 1 txtPacket, i.e. variation of 2 means 1/2 packets is from the txt file
	// i.e. 1/2 if set to 2, or 1/3 if set to 3
	int sockOUT, totalPackets=300, lastSent=0, txtSend=1, n=1, variation=2;
	packet outGoing;
	FILE *file;
	
	//----------------Network code----------------
	// Open sockets
	if((sockOUT = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		DieWithError("socket() failed");
		
	// Construct address structure
	bzero((char *)&genOUT_addr,sizeof(genOUT_addr));		// zeroes out struct before data copied
    genOUT_addr.sin_family = AF_INET;						// specifies Address Family
    genOUT_addr.sin_addr.s_addr = inet_addr(LOCAL_ADDRESS);	// Connect to local address
    genOUT_addr.sin_port = htons(OUTPUT_PORT);				// output port assigned to struct
    // Construct address structure
	bzero((char *)&genOUT2_addr,sizeof(genOUT2_addr));		// zeroes out struct before data copied
    genOUT2_addr.sin_family = AF_INET;						// specifies Address Family
    genOUT2_addr.sin_addr.s_addr = inet_addr(LOCAL_ADDRESS);	// Connect to local address
    genOUT2_addr.sin_port = htons(OUTPUT_PORT2);				// output port assigned to struct
    //--------------End Network code--------------
    
    srand (time(NULL));		// initialize random seed
    
    file = fopen("genStream.txt", "r");
	if(file != NULL) {
		fscanf(file, "Destination:%i.%i.%i.%i Source:%i.%i.%i.%i Port:%i Size:%i", &dtxt[0], &dtxt[1], &dtxt[2], &dtxt[3], &stxt[0], &stxt[1], &stxt[2], &stxt[3], &porttxt, &sizetxt);
		fclose(file);
		printf("Destination:%i.%i.%i.%i Source:%i.%i.%i.%i Port:%i Size:%i\n", dtxt[0], dtxt[1], dtxt[2], dtxt[3], stxt[0], stxt[1], stxt[2], stxt[3], porttxt, sizetxt);
	}
     
	while(n<=totalPackets) {
		if(porttxt < 8)					// checks whether file has inputed values, otherwise txtSend never changes
			txtSend = n % variation;	// txtPacket is 0 every iteration of variable variation, so that createPacket() will create txtPacket
		
		outGoing = createPacket(lastSent, txtSend);	// creates random packet or packet from txt file
		outGoing.sequenceNum = n;		// inserts sequence number
				
		if((n % 2) == 1) {
			if(sendto(sockOUT, &outGoing, MAX_MSG_LEN, 0, (struct sockaddr *)&genOUT2_addr, sizeof(genOUT2_addr)) != MAX_MSG_LEN)
				DieWithError("sendto() failed");
			printf("Packet %i enters bottom switch on port %i at time %i\n", outGoing.sequenceNum, outGoing.fromPort, outGoing.timer);
		} else {
			if(sendto(sockOUT, &outGoing, MAX_MSG_LEN, 0, (struct sockaddr *)&genOUT_addr, sizeof(genOUT_addr)) != MAX_MSG_LEN)
				DieWithError("sendto() failed");
			printf("Packet %i enters top 	switch on port %i at time %i\n", outGoing.sequenceNum, outGoing.fromPort, outGoing.timer);
		}
				
		
		
		lastSent = outGoing.timer;
		
		n++;
	}
	
	return 1;
}


/*	************************
	PACKET CONTROL FUNCTIONS
	************************ */
	
packet createPacket(int lastSent, int txtSend) {
	int dest[4], src[4], packetSize, n, sameTime, maxInterval=10, sameChance=1;
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
		packetSize = rand() % 50;
		newPacket.fromPort = rand() % 8;
	}
	
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
	sameTime = rand() % maxInterval;	// maxInterval in secs (non realtime) between packets
	
	if(sameTime < sameChance)					// (number here divided by above number)% chance of same time
		newPacket.timer = lastSent;
	else {
		if((sameChance == 0) && (sameTime == 0))	// in case sameChance = 0 and sameTime happens to random on 0, can't have same time
			sameTime++;
		newPacket.timer = lastSent + sameTime;	
	}
		
	return newPacket;
}

/*	**************
	MISC FUNCTIONS
	************** */

// Merge 4 numbers into multi-dimensional array
void createIP(int i1, int i2, int i3, int i4, char ip_addr[4][9]) {
	int n,i;
	
	for(i=0;i<4;i++) {	// Zero the ip address
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
	
	for(n=0;n<=length;n++) {	// zero the binary string
		binary[n] = '0';
	}
	
	do {
		remain = decimal % 2;	// whittle down the decimal number
		decimal = decimal / 2;
		temp[k] = remain + '0';	// converts digit 0 or 1 to character '0' or '1'
		k++;
	} while (decimal > 0);
	
	n=length-1;
	for(i=0;i<k;i++) {			// reverse the spelling
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
