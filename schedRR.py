"""
This is the python script framework that will contain the code
to implement the round robin scheduler for TELE9751 - network arch

We will employ pythons builtin sockets as to enable fucntionality withount
any additional libraries for better system compatability

This script as been constructed for Python 2.7, due to syntax familliarity


Created on Thu Apr 24 10:51:47 2017

@author: benjamin zhao
"""
import socket
import struct

HOST = '127.0.0.1'
IN_PORT = 50002
OUT_PORT = 50003
MAX_MSG_LEN = 200


class packet(object):
    '''
    A class to represent a packet and to hold all the associated methods

    Original C definition:
        typedef struct packet packet;
        // Struct of packet being sent between each module
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
    '''

    def __init__(self, data):
        # Keep track of the length of the data
        self.msg_len = len(data)
        # Keep a copy of the raw byte data
        # we should remove this in the final revision to save memory
        self.data = data

        # The real deal, we decode the raw data with unpack_packet and
        # save the variables to the current object
        # The variables will be set within the subfunction

        # 4*9 chars in the array = 36
        self.packet_format = '36c36ch100ciiiiii'
        self.unpack_packet(data)

        remade_data = self.repack_packet()

        print '\nNEW PACKET'
        print data
        print ''
        print remade_data 

        # A check to verify that we are decoding and encoding packets correctly
        assert data == remade_data

    def unpack_packet(self, packet):
        '''
        Function to decode the recieved packet into proper variables
        '''

        obj = struct.unpack(self.packet_format, packet)

        # Set the values for the current packet
        self.ip_dest = self.reconstruct_ip(obj[0:36])
        self.ip_source = self.reconstruct_ip(obj[36:72])
        self.datalength = obj[72]
        self.data = obj[73:173]  # 100 long
        self.frameCheck = obj[173]
        self.fromPort = obj[174]
        self.toPort = obj[175]
        self.sequenceNum = obj[176]
        self.portSequenceNum = obj[177]
        self.timer = obj[178]

        # If for some reason we want to manipulate the raw object
        return obj

    def repack_packet(self):
        '''
        Function to reencode the recieved packet into a c struct for the
        next module
        '''
        obj = []

        # Set the values for the current packet
        obj.extend(self.deconstruct_ip(self.ip_dest))
        obj.extend(self.deconstruct_ip(self.ip_source))
        obj.append(self.datalength)
        obj.extend(self.data)
        obj.append(self.frameCheck)
        obj.append(self.fromPort)
        obj.append(self.toPort)
        obj.append(self.sequenceNum)
        obj.append(self.portSequenceNum)
        obj.append(self.timer)

        data = struct.pack(self.packet_format, *obj)

        assert len(data) == MAX_MSG_LEN

        # If for some reason we want to manipulate the raw object
        return data

    def reconstruct_ip(self, char_arr):
        ''' The char_arr is in a format that contains the bitwise information
            in 8 bit sections (ipv4 addresses) separated by a null character in
            the 9th element e.g.

            [0, 0, 0, 0, 0, 0, 0, 0, null, 0, 0, 0, 0, 0, 0, 0, 0, null ....]
        '''
        def bitlist_to_int(bitlist):
            '''Convert bit list to integer'''
            value = 0
            for bit in bitlist:
                value = (value << 1) | int(bit)
            return value

        # We shall store ipv4's in an array of 8 bit chunks (dot separation)
        ipv4 = []
        ipv4.append(bitlist_to_int(char_arr[0:8]))
        ipv4.append(bitlist_to_int(char_arr[9:17]))
        ipv4.append(bitlist_to_int(char_arr[18:26]))
        ipv4.append(bitlist_to_int(char_arr[27:35]))

        return ipv4

    def deconstruct_ip(self, value_arr):
        ''' The char_arr is in a format that contains the bitwise information
            in 8 bit sections (ipv4 addresses) separated by a null character in
            the 9th element e.g.

            [192.                        : 0                            ,...]
            [0, 0, 0, 0, 0, 0, 0, 0, null, 0, 0, 0, 0, 0, 0, 0, 0, null ....]
        '''
        def bitlist_dot(value):
            # List Comprehension
            bitlist = ['1' if digit == '1' else '0' for digit in format(value, '08b')]
            bitlist.append('\x00')
            return bitlist

        # We shall store ipv4's in an array of 8 bit chunks (dot separation)
        char_arr = []
        for value in value_arr:
            char_arr.extend(bitlist_dot(value))

        return char_arr


class Sched_rr(object):
    '''
    A class to hold all the methods involving the scheduler
    '''
    def __init__(self):
        # Setting up constants (these should be static)
        self.in_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.out_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Binding the sockets to listen on the correct ports

        # The input will always be listening
        self.in_sock.bind((HOST, IN_PORT))
        # The output is a client ready to send data out
        self.out_sock.connect((HOST, OUT_PORT))

    def main_loop(self):
        '''The main loop function'''

        # Main loop
        while True:
            data, addr = self.in_sock.recvfrom(MAX_MSG_LEN + 100)

            curr_packet = packet(data)

            # Do things with current packet

if __name__ == '__main__':
    # initialise the scheduler object
    scheduler = Sched_rr()
    # Execute the main loop
    scheduler.main_loop()
