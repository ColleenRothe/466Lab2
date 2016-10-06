import Network
import argparse
from time import sleep
import hashlib


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32 
        
    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S
        
    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            return None
            #raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S)
        
        
    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S
   
    
    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length :
                            Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S
    
#only use for ack/nack...so can get rid of seq_num
#use previous packet for the acutall message stuff
class Packet_2_1:
    ## the number of bytes used to store packet length
    #seq_num_S_length = 10
    seq_num_length = 5
    length_S_length = 10
    flag_length = 5 
    ## length of md5 checksum in hex
    checksum_length = 32 
        
    def __init__(self, seq_num, flag): # don't care about seq. num or message. just if ack or nack
        self.seq_num = seq_num
        self.flag = flag
        
    @classmethod
    def from_byte_S(self, byte_S): 
        if Packet_2_1.corrupt(byte_S):
            #raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
            #print("corrupt")
            return None
            
        #extract the fields (only 1 for the ack/nack...)
        #same as idea for seq num in 1.0
        seq_num = int(byte_S[Packet_2_1.length_S_length :
                           Packet_2_1.length_S_length+Packet_2_1.seq_num_length])
        flag = int(byte_S[Packet_2_1.length_S_length+Packet_2_1.seq_num_length :
                           Packet_2_1.length_S_length+Packet_2_1.seq_num_length+Packet_2_1.flag_length])
        return self( seq_num, flag)
        
    def get_byte_S(self):
        seq_num_S = str(self.seq_num).zfill(self.seq_num_length)
        flag_S = str(self.flag).zfill(self.flag_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + len(flag_S) + self.checksum_length).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5(str(length_S+seq_num_S+flag_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + flag_S + checksum_S
   
    
    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet_2_1.length_S_length]
        seq_num_S = byte_S[Packet_2_1.length_S_length : Packet_2_1.length_S_length+Packet_2_1.seq_num_length]
        flag_S = byte_S[Packet_2_1.length_S_length+Packet_2_1.seq_num_length : Packet_2_1.length_S_length+Packet_2_1.seq_num_length+Packet_2_1.flag_length]
        checksum_S = byte_S[Packet_2_1.length_S_length+Packet_2_1.seq_num_length+Packet_2_1.flag_length: ]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+flag_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S

    #ack = 1
    def isACK(self):
        if self.flag == 1:
            return True
        else:
            return False
 

    #nak = 0
    def isNAK(self):
        if self.flag == 1:
            return False
        else:
            return True
 
        

class RDT:
    ## latest sequence number used in a packet
    seq_num = 0
    ## buffer of bytes read from network
    byte_buffer = ''
    rcv_seq_num = 1
    
    

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()
        
    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())

    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration
            
    #SENDING:
    #2 states seq_num 0/1
    #State 0:
            #recieve and create packet with seq_num = 0
            #(1) if corrupt or nack or ack with seq_num = 1
                #udt send again with same seq_num
            #(2) if not corrupt and ack with seq_num = 0
                #update seq_num to 1
                #move on to the next state
            #(3) catch all case
    #State 1:
            #same thing...but for the other sequence num.

    

    def rdt_2_1_send(self, msg_S):
        #same as from 1.0 send. need to get data in the if
        p = Packet(self.seq_num, msg_S)
        if p is None:
            print("BAD")
        self.network.udt_send(p.get_byte_S())
            
        while True:
            byte_S = self.network.udt_receive()
            if not(Packet_2_1.corrupt(byte_S) or (len(byte_S) < Packet_2_1.length_S_length) or (len(byte_S) < int(byte_S[0:Packet_2_1.length_S_length]))):
                #create packet from buffer content and add to return string
                packet = Packet_2_1.from_byte_S(byte_S)
                if packet is None or packet.isNAK() or packet.seq_num != self.seq_num:
                    if packet is None:
                        print("corrupt acknowledement")
                    elif packet.isNAK():
                        print("NAK")
                    else:
                        print("wrong sequence acknowledgement")
                    self.network.udt_send(p.get_byte_S())
                elif packet.isACK() and packet.seq_num == self.seq_num:
                    print("ACK")
                    self.seq_num = int(not self.seq_num) # next packet sent will be the other seq_num
                    break
                else:
                    print("nak/ack some how fucked up")
                    self.network.udt_send(p.get_byte_S())

            self.network.udt_send(p.get_byte_S())

                        

     #RECEIVING: 2 States based on last seq_num received
        #State 1: original seq_num sent will be 0 we want to be opposite
                #(1): if corrupt
                    #send nak
                #(2): if not corrupt and seq_num is 0
                    #send an ack
                    #set rcv_seq_num = 0
                #(3): if not corrupt and seq_num = 1
                    #send ack
                #(4): catch all case
        #STATE 0:
                #same, but switch the seq. num stuff

    def rdt_2_1_receive(self):
        #from 1.0
        ret_S = None
        byte_S = self.network.udt_receive()
        if Packet.corrupt(byte_S):
            num = int(not self.rcv_seq_num)
            packet = Packet_2_1(num, 0)
            self.network.udt_send(packet.get_byte_S())
            return None
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                sleep(0.1) #socket timeout in Network.py
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[0:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                sleep(0.1) #socket timeout in Network.py
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            if p is None:
                print("received corrupt packet")
                #send a nak
                num = int(not self.rcv_seq_num)
                packet = Packet_2_1(num, 0)
                self.network.udt_send(packet.get_byte_S())
                self.byte_buffer = self.byte_buffer[length:]
            elif p.seq_num != self.rcv_seq_num:
                print("received correct packet")
                #do stuff from 1.0
                ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                #remove the packet bytes from the buffer
                self.byte_buffer = self.byte_buffer[length:]
                #get to the next state
                self.rcv_seq_num = p.seq_num
                #send ack
                packet = Packet_2_1(p.seq_num, 1)
                self.network.udt_send(packet.get_byte_S())
            elif p.seq_num == self.rcv_seq_num:
                print("receive out of order packet")
                self.byte_buffer = self.byte_buffer[length:]
                #send ack
                packet = Packet_2_1(p.seq_num, 1)
                self.network.udt_send(packet.get_byte_S())
            else:
                print("packet was fucked up somehow")
                #send a nak
                packet = Packet_2_1(rcv_seq_num, 0)
                self.network.udt_send(packet.get_byte_S())
                
                    
    
    def rdt_3_0_send(self, msg_S):
        pass
        
    def rdt_3_0_receive(self):
        pass
        

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_2_1_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_2_1_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        print(rdt.rdt_2_1_receive())
        rdt.rdt_2_1_send('MSG_FROM_SERVER')
        rdt.disconnect()
