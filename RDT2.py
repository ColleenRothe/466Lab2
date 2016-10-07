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
    length_S_length = 10
    flag_length = 10 #??? why not, the other stuff was 10
    ## length of md5 checksum in hex
    checksum_length = 32 
        
    def __init__(self, flag): # don't care about seq. num or message. just if ack or nack
         self.flag = flag
        
    @classmethod
    def from_byte_S(self, byte_S): 
        if Packet_2_1.corrupt(byte_S):
            #raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
            #print("corrupt")
            return None
            
        #extract the fields (only 1 for the ack/nack...)
        #same as idea for seq num in 1.0
        flag = int(byte_S[Packet_2_1.length_S_length :
                           Packet_2_1.flag_length+Packet_2_1.length_S_length])
        return self(flag)
        
    def get_byte_S(self):
        flag_S = str(self.flag).zfill(self.flag_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(flag_S)+ self.checksum_length).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5(str(length_S+flag_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + flag_S + checksum_S
   
    
    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet_2_1.length_S_length]
        flag_S = byte_S[Packet_2_1.length_S_length : Packet_2_1.flag_length+Packet_2_1.flag_length]
        checksum_S = byte_S[Packet_2_1.length_S_length+Packet_2_1.flag_length: ]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+flag_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S

    #ack = 1
    def isACK(self,flag):
        if flag == 1:
            return True
        else:
            return False
 

    #nak = 0
    def isNAK(self,flag):
        if flag == 1:
            return False
        else:
            return True
 
        

class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = ''
    send = 1
    receive = 1
    last_msg = ''
    last_rec = ''
    
    

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
    #2 states... (really 4, but same for 0/1)
    #State 1:
            #recieve and create packet
            #(1) if corrupt or nack
                #udt send
            #(2) if not corrupt and ack
                #update seq num
                #move on to the next state
    #State 2:
            #same thing...but for the other sequence num.

    

    def rdt_2_1_send(self, msg_S):
        #same as from 1.0 send. need to get data in the if
        p = Packet(self.seq_num, msg_S)
        self.network.udt_send(p.get_byte_S())
        self.last_msg = msg_S

        #get into state 1
        if self.send == 1:
            #loop mentioned in class?
            dont_care = True
            while dont_care:
                byte_S = self.network.udt_receive()
                if(len(byte_S) == 52): #don't want the empty stuff

                    packet = Packet_2_1.from_byte_S(byte_S) #2.1?
                    #(1)
                    #if packet is None or packet.isNAK(packet.flag):
                    if packet is not None and packet.isNAK(packet.flag):
                        print("GOT A NAK1")
                        self.network.udt_send(p.get_byte_S())

                    elif packet is None: #packet corrupt
                        print("GOT A corrupt1")
                        self.network.udt_send(p.get_byte_S())
                        byte_S = None
                    elif not packet.corrupt(byte_S) and packet.isACK(packet.flag):
                        print("GOT ACK1")
                        self.seq_num = 0 #(start w/ a 1)
                        self.send = 2 #go to the next state
                        dont_care = False
                    else:
                        print("ELSE 1")
                        print(len(byte_S))

        #get into state 2
        elif self.send == 2:
            #loop mentioned in class?
            dont_care = True
            while dont_care:
                byte_S = self.network.udt_receive()
                if(len(byte_S) == 52): #==

                    packet = Packet_2_1.from_byte_S(byte_S) #2.1?
                    #(1)
                    #if packet is None or packet.isNAK(packet.flag):
                    if packet is not None and packet.isNAK(packet.flag):
                        print("GOT A NAK2")
                        self.network.udt_send(p.get_byte_S())

                    elif packet is None: #packet corrupt
                        print("GOT A corrupt2")
                        self.network.udt_send(p.get_byte_S())
                        byte_S = None
                    elif not packet.corrupt(byte_S) and packet.isACK(packet.flag):
                        print("GOT A ACK2")
                        self.seq_num = 1 #(start w/ a 1)
                        self.send = 1 #go back to the other state
                        dont_care = False
                else:
                    print("ELSE 2")
                    print(len(byte_S))
                        

     #RECEIVING: 2 States
        #State 1:
                #(1): if not corrupt and seq. # = 1
                    #return message like 1.0
                    #send an ack
                    #move on to the next state
                #(2): if corrupt
                    #send nak
                #(3): if not corrupt and seq. # = 0
                    #send ack
        #STATE 2:
                #same, but switch the seq. num stuff

    def rdt_2_1_receive(self):
        #from 1.0
        ret_S = None
        byte_S = None
        while True:
            #problem...sometimes receiving nothing?
            while byte_S is None:
                byte_S = self.network.udt_receive()
                if byte_S:
                    self.byte_buffer += byte_S
                    break
                else:
                    continue
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                sleep(0.1) #socket timeout in Network.py
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                sleep(0.1) #socket timeout in Network.py
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])

            if self.receive == 1:
                if p is None:
                    print("receive 1.1")
                    #send a nak
                    #print("corrupt receive")
                    packet = Packet_2_1(0)
                    self.network.udt_send(packet.get_byte_S())
                    self.byte_buffer = self.byte_buffer[length:]
                    return None
                elif not p.corrupt(p.get_byte_S()) and p.seq_num == 1:
                   
                    
                    print("receive 1.2")
                    #do stuff from 1.0
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    #remove the packet bytes from the buffer
                    self.byte_buffer = self.byte_buffer[length:]
                    #also send the ack
                    packet = Packet_2_1(1)
                    
                    self.network.udt_send(packet.get_byte_S())
                    self.receive = 2
                    #get to the next state
##                    if self.send == 1:
##                        self.send = 2
##                    else:
##                        self.send = 1
                    
                        
                    
                
                elif not p.corrupt(p.get_byte_S()) and p.seq_num == 0:
                    print("receive 1.3")
                    #get to the next state
##                    if self.send == 1:
##                        self.send = 2
##                    else:
##                        self.send = 1
                    
                        
                    #send ack
                    self.byte_buffer = self.byte_buffer[length:]
                    packet = Packet_2_1(1)
                    
                    self.network.udt_send(packet.get_byte_S())
                    
                    

            #same just switch seq_num stuff
            elif self.receive == 2:
                if p is None:
                    
                    
                    #send a nak
                    print("receive 2.1")
                    packet = Packet_2_1(0)
                    self.network.udt_send(packet.get_byte_S())
                    self.byte_buffer = self.byte_buffer[length:]
                    return None
                elif not p.corrupt(p.get_byte_S()) and p.seq_num == 0:
                    print("receive 2.2")
                    
                    
                    #do stuff from 1.0
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    #remove the packet bytes from the buffer
                    self.byte_buffer = self.byte_buffer[length:]
                    #also send the ack
                    packet = Packet_2_1(1)
                    
                    self.network.udt_send(packet.get_byte_S())
                    self.receive = 1
                    #get to the next state
##                    if self.send == 1:
##                        self.send = 2
##                    else:
##                        self.send = 1
                    
 
                elif not p.corrupt(p.get_byte_S()) and p.seq_num == 1:
                    #get to the next state
##                    if self.send == 1:
##                        self.send = 2
##                    else:
##                        self.send = 1
                    
                        

                    print("receive 2.3")
                    self.byte_buffer = self.byte_buffer[length:]
                    #send ack
                    packet = Packet_2_1(1)
                    
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
