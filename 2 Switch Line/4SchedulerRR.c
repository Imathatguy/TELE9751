/* Daniel Paul Iuliano
z3101121
diuliano@gmail.com
Thesis Topic University of New South Wales
Supervisor: Tim Moors
The PC Switch

Scheduler

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>		// socket() & bind()
#include <errno.h>			// for DieWithError() function
#include <arpa/inet.h>		// sockaddr_in

// Defining all the input and output ports of the scheduler
#define INPUT_PORT 50002
#define OUTPUT_PORT 50003
#define LOCAL_ADDRESS "127.0.0.1"
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

typedef struct packetBuffer packetBuffer;
// Declare buffer struct that holds packet struct
struct packetBuffer {
	packet queuedPacket;
	packetBuffer *nextSource;
	packetBuffer *nextSameSource;
};

// Misc functions
void DieWithError(char *errorMessage);
int bin2dec(char *binary);

int main(void) {
	struct sockaddr_in fabOUT_addr;		// client info (fabric) variable, data given when received message
	struct sockaddr_in schedIN_addr;	// struct for incoming packets
	struct sockaddr_in schedOUT_addr;	// struct for outgoing packets
	unsigned int fabAddrLen;			// int to store length of client address (fabric) data when received
	packet recvPacket, outGoing;		// packet struct that will be received
	int sockIN, sockOUT, recvMsgLen, n, ip[4], i=0, port, pIP[4], qIP[4], dropped=0, time=0, lastTime=0, timeToSend=4, maxSameSource=4;
	packetBuffer *current = NULL;		// keep track of where loop is pointing to in queue row
	packetBuffer *newPacket = NULL;		// used when creating new queue element
    packetBuffer *temp = NULL;			// temp packetBuffer element when deleting root of queue row
    packetBuffer *previous[8];			// keep track of previous element in queue
	packetBuffer *nextSend[8];			// pointer to next element to be sent on port n
	packetBuffer *root[8];				// array of queues, queue 0 is for gateway port, 1-7 corresponding to other ports

	//----------------Network code----------------			
	// Open socket
	if((sockIN = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		DieWithError("socket() failed");
	if((sockOUT = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		DieWithError("socket() failed");
		
	// Construct local address structure
	bzero((char *)&schedIN_addr, sizeof(schedIN_addr));	// zeroes out struct before data copied
    schedIN_addr.sin_family = AF_INET;					// specifies Address Family
    schedIN_addr.sin_addr.s_addr = htonl(INADDR_ANY);	// accept from any network interface
    schedIN_addr.sin_port = htons(INPUT_PORT);			// Using port 5002
    // Construct outgoing address structure
	bzero((char *)&schedOUT_addr,sizeof(schedOUT_addr));			// zeroes out struct before data copied
    schedOUT_addr.sin_family = AF_INET;								// specifies Address Family
    schedOUT_addr.sin_addr.s_addr = inet_addr(LOCAL_ADDRESS);		// Connect to local address
    schedOUT_addr.sin_port = htons(OUTPUT_PORT);					// output port 5003
        	
    // Binding above data (address/port/etc) to socket descriptor sock for port 0
    if((bind(sockIN, (struct sockaddr *) &schedIN_addr, sizeof(schedIN_addr))) < 0)
    	DieWithError("bind() failed");
    //--------------End Network code--------------

    for(n=0;n<8;n++) {
		root[n] = NULL;
		nextSend[n] = NULL;
		previous[n] = NULL;
	}
    	
    while(1) {
		if((recvMsgLen = recvfrom(sockIN, &recvPacket, MAX_MSG_LEN, 0, (struct sockaddr *) &fabOUT_addr, &fabAddrLen)) < 0)
    		DieWithError("recvfrom() failed");
    	for(n=0;n<4;n++)
			pIP[n]=bin2dec(recvPacket.ip_source[n]);
    	printf("success: packet %i received on port %i (Src: %i.%i.%i.%i)\n", recvPacket.sequenceNum, recvPacket.fromPort, pIP[0], pIP[1], pIP[2], pIP[3]);
    		
		time = recvPacket.timer;

    	/*************************************************
   		MANAGE PACKETS AND SCHEDULING FOR ARRIVING PACKETS
   		*************************************************/
   		// packet arrives through fabric to a port
   		// assigned to ports queue if not full (if full, drop)
   		// round robin of processing each port for send
   		port = recvPacket.fromPort;
		current = root[port];

		if(current == NULL) {// current packetBuffer is empty on this port, or end of source queue for port; packet goes here
			if((newPacket = (packetBuffer *)malloc(sizeof(packetBuffer))) != NULL){
				for(n=0;n<4;n++) {
					strcpy(newPacket -> queuedPacket.ip_dest[n], recvPacket.ip_dest[n]);
					strcpy(newPacket -> queuedPacket.ip_source[n], recvPacket.ip_source[n]);
				}
				newPacket -> queuedPacket.dataLength = recvPacket.dataLength;
				strcpy(newPacket -> queuedPacket.data, recvPacket.data);
				newPacket -> queuedPacket.frameCheck = recvPacket.frameCheck;
				newPacket -> queuedPacket.fromPort = recvPacket.fromPort;
				newPacket -> queuedPacket.toPort = recvPacket.toPort;
				newPacket -> queuedPacket.sequenceNum = recvPacket.sequenceNum;
				newPacket -> queuedPacket.portSequenceNum = recvPacket.portSequenceNum;
				newPacket -> queuedPacket.timer = recvPacket.timer;
			
				newPacket -> nextSource = NULL;
				newPacket -> nextSameSource = NULL;
				root[port] = newPacket;
			} else
				DieWithError("Out of Memory");
		} else {
			while(current != NULL) {	// check if recvPacket to be queued matches any already queued packet sources
				// compare sources
				for(n=0;n<4;n++) {
					pIP[n]=bin2dec(recvPacket.ip_source[n]);
					qIP[n]=bin2dec(current -> queuedPacket.ip_source[n]);
				}
				if((pIP[0] == qIP[0]) && (pIP[1] == qIP[1]) && (pIP[2] == qIP[2]) && (pIP[3] == qIP[3])) { // found same source IP in queue
					n=1;
					while(current -> nextSameSource != NULL) {	// add to end of that source queue
						current = current -> nextSameSource;
						n++;
					}
					if(n<maxSameSource) {	// if n greater than maxSameSource, too many packets from that source in queue, drop packet until some sent
						// Make new PacketBuffer and add to end
						if((newPacket = (packetBuffer *)malloc(sizeof(packetBuffer))) != NULL){
							for(n=0;n<4;n++) {
								strcpy(newPacket -> queuedPacket.ip_dest[n], recvPacket.ip_dest[n]);
								strcpy(newPacket -> queuedPacket.ip_source[n], recvPacket.ip_source[n]);
							}
							newPacket -> queuedPacket.dataLength = recvPacket.dataLength;
							strcpy(newPacket -> queuedPacket.data, recvPacket.data);
							newPacket -> queuedPacket.frameCheck = recvPacket.frameCheck;
							newPacket -> queuedPacket.fromPort = recvPacket.fromPort;
							newPacket -> queuedPacket.toPort = recvPacket.toPort;
							newPacket -> queuedPacket.sequenceNum = recvPacket.sequenceNum;
							newPacket -> queuedPacket.portSequenceNum = recvPacket.portSequenceNum;
							newPacket -> queuedPacket.timer = recvPacket.timer;
							
							newPacket -> nextSource = NULL;
							newPacket -> nextSameSource = NULL;
							current -> nextSameSource = newPacket;
							current = NULL;	// terminate loop
						} else
							DieWithError("Out of Memory");
					} else {
						printf("Source queue full, packet dropped.\n");
						dropped++;	// increment dropped packet count
						current = NULL;
					}
				} else {
					if(current -> nextSource == NULL) { // if no more entries in queue of sources, and still no match, add another source queue
						if((newPacket = (packetBuffer *)malloc(sizeof(packetBuffer))) != NULL){
							for(n=0;n<4;n++) {
								strcpy(newPacket -> queuedPacket.ip_dest[n], recvPacket.ip_dest[n]);
								strcpy(newPacket -> queuedPacket.ip_source[n], recvPacket.ip_source[n]);
							}
							newPacket -> queuedPacket.dataLength = recvPacket.dataLength;
							strcpy(newPacket -> queuedPacket.data, recvPacket.data);
							newPacket -> queuedPacket.frameCheck = recvPacket.frameCheck;
							newPacket -> queuedPacket.fromPort = recvPacket.fromPort;
							newPacket -> queuedPacket.toPort = recvPacket.toPort;
							newPacket -> queuedPacket.sequenceNum = recvPacket.sequenceNum;
							newPacket -> queuedPacket.portSequenceNum = recvPacket.portSequenceNum;
							newPacket -> queuedPacket.timer = recvPacket.timer;
							
							newPacket -> nextSource = NULL;
							newPacket -> nextSameSource = NULL;
							current -> nextSource = newPacket;
							current = NULL; // terminate loop
						} else
							DieWithError("Out of Memory");
					} else	// check next source queue
						current = current -> nextSource;
				}
			}
		}
		
    	/****************************
		MANAGING NEXT OUTGOING PACKET
		****************************/
		// Send a packet, delete it from queue and shift queue down one, relink up to nextSource in that queue
    	// only run on every 2nd rotation (point of HalfCount variable)
		while(time > lastTime) {	// according to how many seconds per 1packet send, determines how many outgoing packets processed for period time - lastTime
    		for(n=0;n<8;n++) {
	    		if(root[n] != NULL) {
	    			if(nextSend[n] == NULL)
	    				nextSend[n] = root[n];
	    				    			 				    
					for(i=0;i<4;i++) {
						pIP[i]=bin2dec(nextSend[n] -> queuedPacket.ip_dest[i]);
						qIP[i]=bin2dec(nextSend[n] -> queuedPacket.ip_source[i]);
					}
					printf("Packet %i sent out on port %i to IP: %i.%i.%i.%i (Src: %i.%i.%i.%i)\n", nextSend[n]->queuedPacket.sequenceNum, n, pIP[0], pIP[1], pIP[2], pIP[3], qIP[0], qIP[1], qIP[2], qIP[3]);
					// send packet out to either next switch or to analyser
					for(i=0;i<4;i++) {
						strcpy(outGoing.ip_dest[i], nextSend[n] -> queuedPacket.ip_dest[i]);
						strcpy(outGoing.ip_source[i], nextSend[n] -> queuedPacket.ip_source[i]);
					}
					outGoing.dataLength = nextSend[n] -> queuedPacket.dataLength;
					strcpy(outGoing.data, nextSend[n] -> queuedPacket.data);
					outGoing.frameCheck = nextSend[n] -> queuedPacket.frameCheck;
					outGoing.fromPort = nextSend[n] -> queuedPacket.fromPort;
					outGoing.toPort = nextSend[n] -> queuedPacket.toPort;
					outGoing.sequenceNum = nextSend[n] -> queuedPacket.sequenceNum;
					outGoing.portSequenceNum = nextSend[n] -> queuedPacket.portSequenceNum;
					outGoing.timer = nextSend[n] -> queuedPacket.timer;
			
					if(sendto(sockOUT, &outGoing, MAX_MSG_LEN, 0, (struct sockaddr *)&schedOUT_addr, sizeof(schedOUT_addr)) != MAX_MSG_LEN)
						DieWithError("sendto() failed");
												
					if(nextSend[n] -> nextSameSource == NULL) {
						temp = nextSend[n];			// assign temp for freeing element
						if(previous[n] == NULL) 	// need to check if first in list, if so, then 
							root[n] = nextSend[n] -> nextSource;
						else						// otherwise, previous element linked to nextSend[n] -> nextSource;
							previous[n] -> nextSource = nextSend[n] -> nextSource;
						nextSend[n] = nextSend[n] -> nextSource;
						if(nextSend[n] == NULL) {	// if at end of queue, go back to start
							nextSend[n] = root[n];
							previous[n] = NULL;		// back to start of port queue, so previous is NULL
						}
						free(temp);
					} else {						// more than one source
						temp = nextSend[n];			// assign temp for freeing element
						nextSend[n] -> nextSameSource -> nextSource = nextSend[n] -> nextSource;
						if(previous[n] == NULL) { 	// need to check if first in list, if so, then 
							root[n] = nextSend[n] -> nextSameSource;
							previous[n] = root[n];
						} else	{					// otherwise, previous element linked to nextSend[n] -> nextSameSource
							previous[n] -> nextSource = nextSend[n] -> nextSameSource;
							previous[n] = nextSend[n] -> nextSameSource;	// and a previous now equal to nextSend[n] -> nextSameSource
						}
						nextSend[n] = nextSend[n] -> nextSource;
						if(nextSend[n] == NULL) {
							nextSend[n] = root[n];
							previous[n] = NULL;
						}
						free(temp);
					}
					
				}
	    	}
	    	// 1 packet sent every timeToSend of seconds (not real time) for time interval between lastTime and current time
	    	// checks size of packet, if substantially large, more time is taken to process packet
	    	if(outGoing.dataLength > 50)
				lastTime = lastTime + timeToSend;	// extra time if packet is large
			lastTime = lastTime + timeToSend;
			
			// TESTING print scheduler queues
			for(n=0;n<8;n++) {
				printf("[Port %i queue]", n);
				current = root[n];
				while(current != NULL) {
					printf("\n");
					temp = current;
					while(temp != NULL) {
						for(i=0;i<4;i++)
							ip[i] = bin2dec(temp -> queuedPacket.ip_source[i]);
						printf("%i.%i.%i.%i -> ", ip[0], ip[1], ip[2], ip[3]);
						temp = temp -> nextSameSource;
					}
					current = current -> nextSource;
				}
				printf("\n");
			}
		
			printf("Dropped packets = %i\n", dropped); // print how many packets are dropped if the sameSource queue was full
		}
		
		// lastTime is now the timeStamp of time that last packet was sent out
		// so when new time is calculated from recvPacket.timer, amount of time
		// from 'lastTime' to 'time' is how much time to process packets for sending
		lastTime = time + (lastTime - time);
	}
	     
	return 1;    // never reaches here
}

void DieWithError(char *errorMessage)
{
    perror(errorMessage);
    exit(1);
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
