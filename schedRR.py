"""
This is the python script framework that will contain the code
to implement the round robin scheduler for TELE9751 - switching arch

We will employ pythons built-in sockets as to enable functionality without
any additional libraries for better system compatibility

This script as been constructed for Python 2.7, due to syntax familiarity

Created on Thu Apr 24 10:51:47 2017
"""
# For the packet Class
import struct
# For the WRR class
import Queue
import fractions
# For the main function
import json
import socket


class Packet(object):
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

    Attributes:

        ip_dest
        ip_source
        datalength
        data
        frameCheck
        fromPort
        toPort
        sequenceNum
        portSequenceNum
        timer
    '''
    # TODO implement more error/malformation checks

    def __init__(self, data):
        '''
        Initialisation of a new Packet requires the data received
        from the framework input port, to be reconstructed into usable
        python data-structures.

        validate_packet() will also be called to ensure the validity of
        the received packet
        '''

        self.invalid = True

        # The real deal, we decode the raw data with unpack_packet and
        # save the variables to the current object
        # The variables will be set within the sub-function

        # 4*9 chars in the array = 36
        # c = char, h = short, i = int
        # the format below is the sequential order of c struct
        # as defined above.
        self.packet_format = '36c36ch100ciiiiii'
        try:
            self.unpack_packet(data)
            remade_data = self.repack_packet()

            # Unit test: Can be removed after verification.
            # A check to verify that we are de/encoding packets correctly
            assert data == remade_data

            self.validate_packet()

            # Mark this packet as valid, if operations complete successfully
            self.invalid = False
        except:
            print 'Make - Remake - Validate Failed'

    def validate_packet(self):
        '''
        Function to verify the date fields of the packet structure.

        Future works to expand checks to every field.

        Currently only checking:
            IP source
            IP destination
            Data Length
        '''

        for seg in self.ip_dest:
            # 255 is the max value an ipv4 address can have
            assert int(seg) < 256
        for seg in self.ip_source:
            # 255 is the max value an ipv4 address can have
            assert int(seg) < 256

        assert self.datalength < 101

        # TODO make a test to check data validity
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
        Function to decode the received packet into python data-structures,

        For use in the current python-based module.
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
        Function to re-encode the received packet into a C struct,

        For the use in the next switch framework module.
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
        '''
        Used in unpack_packet() to convert IP to integer fields

        The char_arr is in a format that contains the bitwise information
        in 8 bit sections (ipv4 addresses) separated by a null character in
        the 9th element e.g.

        [0, 0, 0, 0, 0, 0, 0, 0, null, 0, 0, 0, 0, 0, 0, 0, 0, null, ...]
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
        '''
        Used in repack_packet() to convert IP to chars

        The char_arr is in a format that contains the bitwise information
        in 8 bit sections (ipv4 addresses) separated by a null character in
        the 9th element e.g.

        [192.                        : 0                           , ...]
        [0, 0, 0, 0, 0, 0, 0, 0, null, 0, 0, 0, 0, 0, 0, 0, 0, null, ...]
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


# This is create a a class as there will be multiple of these operating
# Concurrently and behaving exactly the same as each other.
class WRRScheduler(object):
    '''
    A class to hold all the methods involving a single output weighted
    round robin scheduler.
    '''
    def __init__(self, output_port, output_specific_overrides,
                 ip_overrides, global_config, queue_size=0):
        '''
        Initialises a WRRScheduler class.

        Inputs:
            output_port:        An identifier for the current output port
            output_specific_overrides: IP source overrides specific for this
                                port.
            ip_overrides:       IP source global overrides
            global_config:      IP source default weight and mean packet length
            queue_size:         Defines now many packets can be stored
                                in each queue (Default is infinite)

        '''
        # A dictionary holder for the different ip queues
        self.input_queues = {}
        self.ips_tobeserved = Queue.Queue()
        self.output_port = output_port
        self.next_packet = None

        self.max_packets_per_queue = queue_size

        # Unpack the weights as provided from the input
        self.ip_config = {'default': global_config}
        # Unpack the ip specific weights
        if ip_overrides is not None:
            for ip in ip_overrides:
                self.ip_config[ip] = ip_overrides[ip]
        if output_specific_overrides is not None:
            for ip in output_specific_overrides:
                self.ip_config[ip] = output_specific_overrides[ip]

        # Rounding of the precision for packets/round
        self.rounding_precision = 100

        self.validate_configs()

    def validate_configs(self):
        '''
        The robustness check of the IP configurations,
        Ensures that:
            - keys are valid,
            - values are valid,
            - weights > 0,
            - lengths > 0,
        '''

        def check_values(ip_config):
            '''
            Trys to resolve parameters as floats, if string will error
            '''
            try:
                # We also do not want these to be 0
                if float(ip_config['weight']) <= 0:
                    return False
                if float(ip_config['mean_length']) <= 0:
                    return False
            except (ValueError, KeyError):
                return False
            else:
                return True

        # Check the global configs (if corrupt, default to 1)
        if not check_values(self.ip_config['default']):
            print 'Improper Default Configurations on Output %s' % self.output_port
            print 'Using defaults'
            self.ip_config['default'] = {'weight': 1, 'mean_length': 1}

        # Check all the other configs
        for check_ip in list(self.ip_config.keys()):
            if not check_values(self.ip_config[check_ip]):
                # If the configuration for this ip is invalid/broken
                # remove it from the configs that are being used
                self.ip_config.pop(check_ip)
                print 'Improper Configuration for IP %s on Output %s' % (
                    check_ip, self.output_port
                )
                print 'Using defaults'

    def recompute_round_service(self):
        '''
        We recompute the weights of the current active queues for the next
        round of service.
        '''
        # Get a list of active queues that are active for this round
        active_ips = self.input_queues.keys()

        # If there are no active ips, remain idle until there is activity
        if len(active_ips) == 0:
            return

        # If there are active IPs continue processing

        # get the relevant ip configs from our config holder
        default_config = self.ip_config['default']
        active_configs = []

        for curr_ip in active_ips:
            # Try get an override, or take default values
            ip_config = self.ip_config.get(curr_ip, default_config)
            # Make a normalisation fraction
            ip_packet_per_round = fractions.Fraction(
                ip_config['weight'],
                ip_config['mean_length'])
            # Limit the denominator so we don't have many packets per round
            ip_packet_per_round.limit_denominator(self.rounding_precision)

            active_configs.append((curr_ip, ip_packet_per_round))

        # Create integer version of previous
        def make_whole(configs):
            '''
            Convert our previous struct to normalise the packets per round into
            workable integers
            '''
            ips = [a[0] for a in configs]
            fracs = [a[1] for a in configs]
            denoms = [frac.denominator for frac in fracs]
            while max(denoms) != 1:
                largest_denom = max(denoms)
                temp_fracs = [largest_denom*frac for frac in fracs]
                fracs = temp_fracs

                denoms = [frac.denominator for frac in fracs]
            return zip(ips, [frac.numerator for frac in fracs])

        active_configs = make_whole(active_configs)

        # TODO: Do more rounding with the numerators if they are too large

        for config in active_configs:
            this_ip = config[0]
            packets_this_round = config[1]
            # Enqueue the number of packets we need onto the waiting queue
            for increment in range(min(packets_this_round,
                                       self.input_queues[this_ip].qsize())):
                self.ips_tobeserved.put(this_ip)

    def print_status(self):
        '''
        Prints to console the status of the current scheduler.
        '''
        print_str = ('Output %s pending sources: ' % self.output_port)

        if len(self.input_queues.keys()) == 0:
            # print_str += 'Empty'
            pass

        else:
            # print_str += 'IP queue : packets in queue\n'
            for waiting_ip in self.input_queues:
                print_str += '%s : %i ' % (waiting_ip,
                                           self.input_queues[waiting_ip].qsize())

        print print_str

    def put_packet(self, packet):
        '''
        Method to allow a caller to insert a new Packet into the control of
        this scheduler.
        '''
        # we process the ip as  string, because it's easier
        source_ip = ('%i.%i.%i.%i') % (packet.ip_source[0],
                                       packet.ip_source[1],
                                       packet.ip_source[2],
                                       packet.ip_source[3])
        # See if an input queue for this ip already exists
        # If not make a new queue for the packet
        if source_ip not in self.input_queues:
            self.input_queues[source_ip] = Queue.Queue(self.max_packets_per_queue)

        # Put the packet onto the proper queue, drop if no space
        try:
            self.input_queues[source_ip].put_nowait(packet)
        except Queue.Full:
            # Drop the packet
            print 'Packet %s dropped.' % packet.sequenceNum

    def ready_next_packet(self):
        '''
        With the current state of the scheduler determine what packet is the
        next to leave the system.
        '''
        if self.ips_tobeserved.qsize() > 0:
            next_ip = self.ips_tobeserved.get()
            # If there is a packet in the queue, serve it
            if next_ip in self.input_queues:
                self.next_packet = self.input_queues[next_ip].get()

                # Check if there are any packets left, if not destroy the queue
                if self.input_queues[next_ip].empty():
                    self.input_queues.pop(next_ip, None)
            # Else do nothing
        # Our serve queue is empty, so we repopulate it, with recompute
        else:
            self.recompute_round_service()

    def output_next_packet(self):
        '''
        Return the next scheduled Packet to the caller for framework sending.
        '''
        if self.next_packet is not None:
            if self.next_packet.datalength > 50:
                self.next_packet.timer += 50
            self.next_packet.timer += 50

            output = self.next_packet

            self.next_packet = None
            return output
        else:
            return None


# This is the sample api as the weighted round robin class,
# But implemented for basic round robin initially
class RRScheduler(object):
    '''
    A class to hold all the methods involving a single output
    round robin scheduler.
    '''
    def __init__(self, output_port, queue_size=0):
        '''
        Initialises a RRScheduler class.

        Inputs:
            output_port:        An identifier for the current output port
            queue_size:         Defines now many packets can be stored
                                in each queue (Default is infinite)
        '''
        # A dictionary holder for the different ip queues
        self.input_queues = {}
        self.ips_tobeserved = Queue.Queue()
        self.output_port = output_port
        self.next_packet = None

    def put_packet(self, packet):
        '''
        Method to allow a caller to insert a new Packet into the control of
        this scheduler.
        '''
        # we process the ip as  string, because it's easier
        source_ip = ('%i.%i.%i.%i') % (packet.ip_source[0],
                                       packet.ip_source[1],
                                       packet.ip_source[2],
                                       packet.ip_source[3])
        # See if an input queue for this ip already exists
        # If not make a new queue for the packet
        if source_ip not in self.input_queues:
            self.input_queues[source_ip] = Queue.Queue()
            self.ips_tobeserved.put(source_ip)
        # Put the packet onto the proper queue
        self.input_queues[source_ip].put(packet)

    def ready_next_packet(self):
        '''
        With the current state of the scheduler determine what packet is the
        next to leave the system.
        '''
        if self.ips_tobeserved.qsize() > 0:
            next_ip = self.ips_tobeserved.get()
            self.next_packet = self.input_queues[next_ip].get()

            # Check if there are any packets left, if not destroy this queue
            if self.input_queues[next_ip].empty():
                self.input_queues.pop(next_ip, None)
            else:
                # re-queue the ip to be serviced
                self.ips_tobeserved.put(next_ip)

    def output_next_packet(self):
        '''
        Return the next scheduled Packet to the caller for framework sending.
        '''
        if self.next_packet is not None:
            if self.next_packet.datalength > 50:
                self.next_packet.timer += 50
            self.next_packet.timer += 50

            output = self.next_packet

            self.next_packet = None
            return output
        else:
            return None

# The Main function for when this file gets invoked.
if __name__ == '__main__':

    ########################################################################
    # Retrieve the scheduler settings from controller
    # Plan: to implement as JSON format that could be transmitted over ip
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

    source_queue_size = our_config['source_queue_size']
    time_to_send = our_config['time_to_send']

    # DEBUG about system framework
    debug_str = (('Initialising schedRR.py ...\n') +
                 ('Communications on HOST: %s\n' % HOST) +
                 ('Listening on port: %s\n' % IN_PORT) +
                 ('Outputting on port: %s\n' % OUT_PORT) +
                 ('Expecting Framework data structs / ') +
                 ('\"packets\" of length: %s\n' % MAX_MSG_LEN))

    print debug_str

    ########################################################################
    # Initialising the input port queues on the outputs
    ########################################################################
    # For every Ouput Port in the switch
    output_sched_holder = []

    for output_n in range(NUM_OUTPUT):
        # Determine if there are output specific overrides
        input_weights = None
        if str(output_n) in output_overrides:
            input_weights = output_overrides[str(output_n)]

        # Initialise a scheduler, and add it to the holder
        output_sched_holder.append(
            WRRScheduler(output_n, input_weights, ip_overrides, global_weight,
                         queue_size=source_queue_size)
        )

    ########################################################################
    # Initialising the Framework communications
    ########################################################################
    # Setting up constants (these should be static)
    in_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    out_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Binding the sockets to listen on the correct ports
    # The input will always be listening
    in_sock.bind((HOST, IN_PORT))
    # The output is a client ready to send data out
    out_sock.connect((HOST, OUT_PORT))

    # Set a socket time-out to allow the system to DIE gracefully if no flows
    # in_sock.settimeout(20)
    # out_sock.settimeout(0.5)

    print '\nCompleted WRR Scheduler initialisation'

    # accumulate the packets for DEBUGing
    # packet_collector = []
    ########################################################################
    # The Main loop
    ########################################################################

    our_time = 0

    # If we want to do multi-threading of the different schedulers we can here
    while True:
        ####################################################################
        # Retrieve and handle the incoming framework packet
        ####################################################################
        data, addr = in_sock.recvfrom(MAX_MSG_LEN)

        # current_packet
        if data is not None:
            current_packet = Packet(data)

            if current_packet.invalid:
                print 'Malformed Packet Dropped'
                continue

            # Put the Incoming packet to the correct output port scheduler
            output_sched_holder[current_packet.toPort].put_packet(current_packet)

            # Once the packet is placed onto the output scheduler, we should
            # be complete on the input side of things

            # Do things with current packet
            print 'Success Input: packet %i in on port %i (Src: %s.%s.%s.%s) to port %i' % (
                int(current_packet.sequenceNum), int(current_packet.fromPort),
                current_packet.ip_source[0], current_packet.ip_source[1],
                current_packet.ip_source[2], current_packet.ip_source[3],
                int(current_packet.toPort)
            )

            sim_time = current_packet.timer

            # Reset our time if sequence resets
            if current_packet.sequenceNum == 0:
                our_time = 0

        ####################################################################
        # Invoke the schedulers to make a output decision and do the output
        # to the next stage
        ####################################################################
        while sim_time >= our_time:
            our_time += time_to_send

            # For every output scheduler
            for scheduler in output_sched_holder:
                # Prepare the next Packet for sending
                scheduler.ready_next_packet()
                # Retrieve the next Packet for sending to the framework
                send_packet = scheduler.output_next_packet()
                # Only send if there is a Packet.
                if send_packet is not None:
                    # Send the Packet, after repacking it in a C format
                    out_sock.sendall(send_packet.repack_packet())
                    # Debug messages
                    print 'Success Output: packet %i out on port %i (Src: %s.%s.%s.%s) from port %i' % (
                        int(send_packet.sequenceNum), scheduler.output_port,
                        send_packet.ip_source[0], send_packet.ip_source[1],
                        send_packet.ip_source[2], send_packet.ip_source[3],
                        send_packet.fromPort
                    )

            # Debug messages
            for scheduler in output_sched_holder:
                scheduler.print_status()
