/* Daniel Paul Iuliano
z3101121
diuliano@gmail.com
Thesis Topic University of New South Wales
Supervisor: Tim Moors
The PC Switch

Analyser

Receives all packets that make it through and determine:
which packets were dropped
percentage of success
etc

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>		// socket() & bind()
#include <errno.h>			// DieWithError() function
#include <arpa/inet.h>		// sockaddr_in
#include <math.h>			// mod and other math

// Defining all the input and output ports of the scheduler
#define INPUT_PORT 50003
#define MAX_MSG_LEN 200

typedef struct packet packet; // Struct of packet being sent between each module
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
// Size 36 + 36 + 4 + 100 + 4 + 4 + 4= 190

typedef struct packetList packetList;	// stores packet as it arrives for a list
struct packetList {
	packet recv;
	packetList *next;
};

// Misc functions
void DieWithError(char *errorMessage);

int main(void) {
	struct sockaddr_in schedOUT_addr;		// client info (scheduler) variable, data given when received message
	struct sockaddr_in analIN_addr;			// struct for incoming packets
	unsigned int schedAddrLen;				// int to store length of client address (scheduler) data when received
	packet recvPacket;						// packet struct that will be received
	packetList *current = NULL;
	packetList *root = NULL;
	packetList *prev = NULL;
	int sockIN, recvMsgLen, n, count=1, high=0, interval=50;
	float ratio=0, throughput=0;
	
	//----------------Network code----------------	
	// Open socket
	if((sockIN = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		DieWithError("socket() failed");
		
	// Construct local address structure
	bzero((char *)&analIN_addr, sizeof(analIN_addr));	// zeroes out struct before data copied
    analIN_addr.sin_family = AF_INET;					// specifies Address Family
    analIN_addr.sin_addr.s_addr = htonl(INADDR_ANY);	// accept from any network interface
    analIN_addr.sin_port = htons(INPUT_PORT);			// Using port 50003
    
    // Binding above data (address/port/etc) to socket descriptor sockIN
    if((bind(sockIN, (struct sockaddr *) &analIN_addr, sizeof(analIN_addr))) < 0)
    	DieWithError("bind() failed");
    //--------------End Network code--------------

    while(1) {
	 	if((recvMsgLen = recvfrom(sockIN, &recvPacket, MAX_MSG_LEN, 0, (struct sockaddr *) &schedOUT_addr, &schedAddrLen)) < 0)
    		DieWithError("recvfrom() failed");
    	
    	// every received packed is stored in a linkList in order of arrival 		
    	if((current = (packetList *)malloc(sizeof(packetList))) != NULL){
			for(n=0;n<4;n++) {
				strcpy(current -> recv.ip_dest[n], recvPacket.ip_dest[n]);
				strcpy(current -> recv.ip_source[n], recvPacket.ip_source[n]);
			}
			current -> recv.dataLength = recvPacket.dataLength;
			strcpy(current -> recv.data, recvPacket.data);
			current -> recv.frameCheck = recvPacket.frameCheck;
			current -> recv.fromPort = recvPacket.fromPort;
			current -> recv.toPort = recvPacket.toPort;
			current -> recv.sequenceNum = recvPacket.sequenceNum;
			current -> recv.portSequenceNum = recvPacket.portSequenceNum;
			current -> recv.timer = recvPacket.timer;
			if(root == NULL)
				root = current;
			else
				prev -> next = current;
			prev = current;
		} else {
			printf("Out of Memory");
			exit(0);
		}
    	
		// every number of packets equal to interval, print out summary of info
		n=0;
    	if(count % interval == 0) {
	    	current = root;
	    	high = current -> recv.sequenceNum;
	    	printf("Received packets: ");
	    	while(current != NULL) {
	    		printf("%i, ", current -> recv.sequenceNum);
	    		if(current -> recv.sequenceNum > high)
	    			high = current -> recv.sequenceNum;
	    		current = current -> next;
	    		n++;
    		}
    		// calculate ratio (% successfully received) and throughput (packets per second)
    		ratio = n / (recvPacket.sequenceNum * 1.0);	// timsed by 1.0 to conver to floating point for division
    		throughput = n / (recvPacket.timer * 1.0);
	    	printf("\nReceived packets: %i		Expected packets: %i\nRatio of success: %f%%\nThroughput (packets/second): %f\n", n, recvPacket.sequenceNum, ratio, throughput);
	    	ratio = 0;
    	}
    	
    	count++;	// increment recv packets
	}
	
    return 1;    	
}

void DieWithError(char *errorMessage)
{
    perror(errorMessage);
    exit(1);
}
