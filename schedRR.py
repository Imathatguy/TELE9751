"""
This is the python script framework that will contain the code
to implement the round robin scheduler for TELE9751 - network arch

We will employ pythons builtin sockets as to enable fucntionality withount
any additional libraries for better system compatability

This script as been constructed for Python 2.7, due to syntax familliarity


Created on Thu Apr 24 10:51:47 2017

@author: benjamin zhao
"""

import struct

class packet(object):
    # TODO implement error/malformeation checks
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
        self.invalid = True

        # The real deal, we decode the raw data with unpack_packet and
        # save the variables to the current object
        # The variables will be set within the subfunction

        # 4*9 chars in the array = 36
        self.packet_format = '36c36ch100ciiiiii'
        try:
            self.unpack_packet(data)
            remade_data = self.repack_packet()

            # print '\nNEW PACKET'
            # print data
            # print ''
            # print remade_data

            # Unit test: Can be removed after verification.
            # A check to verify that we are decoding and encoding packets correctly
            assert data == remade_data

            self.validate_packet()

            # Mark this packet as valid, if operations complete successfully
            self.invalid = False
        except:
            print 'Make - Remake - Validate Failed'

    def validate_packet(self):
        '''
        Function to verify the fields in the packet structure
        '''

        for seg in self.ip_dest:
            # 255 is the max value an ipv4 address can have
            assert int(seg) < 256
        for seg in self.ip_source:
            # 255 is the max value an ipv4 address can have
            assert int(seg) < 256

        assert self.datalength < 101

        # TODO make a test to chec data validity
        # self.data # 100 long

        # TODO perform a crc on the data to verify with the frame check
        # self.frameCheck

        # TODO make checks on these?
        # self.fromPort
        # self.toPort
        # self.sequenceNum
        # self.portSequenceNum
        # self.timer

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


import socket
import Queue
import json


# This is create a a class as there will be multiple of these operating
# Concurrently and behaving exactly the same as each other.
class wrr_scheduler(object):
    '''
    A class to hold all the methods involving a single output scheduler

    num_inputs defines now many input queues exist per output
    queue_size defines now many packets can be stored in each queue before drop
    (Default is infinite for debug reasons)
    '''
    def __init__(self, output_port, output_specfic_overrides,
                 ip_overrides, global_weight, queue_size=0):

        # A dictionary holder for the diffrent ip queues
        self.input_queues = {}
        self.ips_tobeserved = Queue.Queue()
        self.output_port = output_port
        self.next_packet = None

        # TODO: Normalise the weights with the mean packet length

        # Unpack the weights as provided from the input
        self.ip_weights = {'default': global_weight}
        # Unpack the ip specific weights
        if ip_overrides is not None:
            for ip in ip_overrides:
                self.ip_weights[ip] = ip_overrides[ip]
        if output_specfic_overrides is not None:
            for ip in output_specfic_overrides:
                self.ip_weights[ip] = output_specfic_overrides[ip]

        # TEMPOARY BASIC ROUND ROBIN POINTER
        self.last_served = 0

    def put_packet(self, packet):
        # we process the ip as  string, because it's easier
        source_ip = ('%i.%i.%i.%i') % (packet.ip_source[0], packet.ip_source[1], packet.ip_source[2], packet.ip_source[3])
        # See if an input queue for this ip already exists
        # If not make a new queue for the packet
        if source_ip not in self.input_queues:
            self.input_queues[source_ip] = Queue.Queue()
            self.ips_tobeserved.put(source_ip)
        # Put the packet onto the proper queue
        self.input_queues[source_ip].put(packet)

        # TODO renormalise the weights of all other ips, as there is a new weight to consider

    def ready_next_packet(self):
        # TODO: See which ip to serve next based of normalised weights and rounds
        if self.ips_tobeserved.qsize() > 0:
            next_ip = self.ips_tobeserved.get()
            self.next_packet = self.input_queues[next_ip].get()

            # Check if there are any packets left, if not destroy this queue
            if self.input_queues[next_ip].empty():
                self.input_queues.pop(next_ip, None)
            else:
                # requeue the ip to be serviced
                self.ips_tobeserved.put(next_ip)

    def output_next_packet(self):
        if self.next_packet is not None:
            if self.next_packet.datalength > 50:
                self.next_packet.timer += 50
            self.next_packet.timer += 50

            output = self.next_packet

            self.next_packet = None
            return output
        else:
            return None

# Main Schduler moved out of class into the main function to allow interactive
# debugging
if __name__ == '__main__':

    ########################################################################
    # Retrieve the scheduler settings from controller
    # Plan: to inplement as JSON format that could be transmissted over ip
    # or just as easily stored as text
    ########################################################################
    # Currently reading from a file, but can be retrieved from a url
    with open('config.json') as config_file:
        config = json.load(config_file)

    # Unpack the configuration settings from our schedRR JSON
    # the JSON is for variable readability,
    # but in code the variables are shorter for coding ease
    our_config = config['schedRR']

    HOST = our_config['framework_host']
    IN_PORT = our_config['framework_input_port']
    OUT_PORT = our_config['framework_output_port']
    MAX_MSG_LEN = our_config['max_msg_len']

    NUM_OUTPUT = our_config['num_output_ports']

    output_overrides = our_config['individual_output_configs']
    ip_overrides = our_config['individual_ip_configs']
    global_weight = our_config['global_ip_configs']

    # DEBUG about system framework
    debug_str = (('Initialising schedRR.py ...\n') +
                 ('Communications on HOST: %s\n' % HOST) +
                 ('Listening on port: %s\n' % IN_PORT) +
                 ('Outputting on port: %s\n' % OUT_PORT) +
                 ('Expecting Framework data structs / ') +
                 ('\"packets\" of lenght: %s\n' % MAX_MSG_LEN))

    print debug_str

    ########################################################################
    # Initialising the input port queues on the outputs
    ########################################################################
    # For every Ouput Port in the switch
    output_sched_holder = []

    for output_n in range(NUM_OUTPUT):
        # Determine if there are output specfic overrides
        input_weights = None
        if str(output_n) in output_overrides:
            input_weights = output_overrides[str(output_n)]

        # Initialise a scheduler, and add it to the holder
        output_sched_holder.append(
            wrr_scheduler(output_n, input_weights, ip_overrides, global_weight)
        )

    ########################################################################
    # Initialising the Framework comunications
    ########################################################################
    # Setting up constants (these should be static)
    in_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    out_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Binding the sockets to listen on the correct ports
    # The input will always be listening
    in_sock.bind((HOST, IN_PORT))
    # The output is a client ready to send data out
    out_sock.connect((HOST, OUT_PORT))

    # Set a socket timeout to allow the system to DIE gracefully if no flows
    in_sock.settimeout(20)
    out_sock.settimeout(0.5)

    print '\nCompleted WRR Scheduler initialisation'

    # accumulate the packets for DEBUGing
    packet_collector = []
    ########################################################################
    # The Main loop
    ########################################################################

    # If we want to do multi-threading of the diffrent schedulers we can here
    while True:
        ####################################################################
        # Retreive and handle the incoming framework packet
        ####################################################################
        data, addr = in_sock.recvfrom(MAX_MSG_LEN)

        # current_packet
        if data is not None:
            c_p = packet(data)

            if c_p.invalid:
                print 'Malformed Packet Dropped'
                continue

            # distribute the Incoming packet to the correct output port scheduler
            output_sched_holder[c_p.toPort].put_packet(c_p)

            # Debug code for packets
            packet_collector.append(c_p)

            # Do things with current packet
            print 'Success: packet %i in port %i (Src: %s.%s.%s.%s)' % (
                int(c_p.sequenceNum), int(c_p.fromPort), c_p.ip_source[0],
                c_p.ip_source[1], c_p.ip_source[2], c_p.ip_source[3]
            )

        ####################################################################
        # Invoke the schdulers to make a output decision and do the output
        # to the next stage (TEMPOARY RR)
        ####################################################################

        for scheduler in output_sched_holder:
            scheduler.ready_next_packet()
            send_packet = scheduler.output_next_packet()
            if send_packet is not None:
                out_sock.sendall(send_packet.repack_packet())
                print 'Successfully sent on port %i' % scheduler.output_port
