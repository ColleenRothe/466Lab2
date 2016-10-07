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
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
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
    
class Packet_2_1:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ACK_length = 1
    NAK_length = 1
    ## length of md5 checksum in hex
    checksum_length = 32 
        
    def __init__(self, seq_num, ACK, NAK, msg_S): # added ACK and NAK
        self.seq_num = seq_num
        self.ACK = ACK
        self.NAK = NAK
        self.msg_S = msg_S
        
    @classmethod
    # need to change return for ACK and NAK?
    def from_byte_S(self, byte_S): # added NAK and ACK
        if Packet_2_1.corrupt(byte_S):
            return None
            # raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet_2_1.length_S_length :
                             Packet_2_1.length_S_length+Packet_2_1.seq_num_S_length])
        ACK = int(byte_S[Packet_2_1.length_S_length+Packet_2_1.seq_num_S_length:
                         Packet_2_1.length_S_length+Packet_2_1.seq_num_S_length+Packet_2_1.ACK_length])
        NAK = int(byte_S[Packet_2_1.length_S_length+Packet_2_1.seq_num_S_length+Packet_2_1.ACK_length:
                         Packet_2_1.length_S_length+Packet_2_1.seq_num_S_length+Packet_2_1.ACK_length+Packet_2_1.NAK_length])
        msg_S = byte_S[Packet_2_1.length_S_length+Packet_2_1.seq_num_S_length+Packet_2_1.ACK_length+Packet_2_1.NAK_length+Packet_2_1.checksum_length :]
        return self(seq_num, ACK, NAK, msg_S)
        
    # change return for ACK and NAK?    
    def get_byte_S(self): # added NAK and ACK
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.ACK_length + self.NAK_length + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        ACK_S = str(self.ACK).zfill(self.ACK_length)
        NAK_S = str(self.NAK).zfill(self.NAK_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+ACK_S+NAK_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + ACK_S + NAK_S + checksum_S + self.msg_S
   
    
    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet_2_1.length_S_length]
        seq_num_S = byte_S[Packet_2_1.length_S_length :
                           Packet_2_1.seq_num_S_length+Packet_2_1.seq_num_S_length]
        ACK_S = byte_S[Packet_2_1.length_S_length+Packet_2_1.seq_num_S_length:
                       Packet_2_1.length_S_length+Packet_2_1.seq_num_S_length+Packet_2_1.ACK_length]
        NAK_S = byte_S[Packet_2_1.length_S_length+Packet_2_1.seq_num_S_length+Packet_2_1.ACK_length:
                       Packet_2_1.length_S_length+Packet_2_1.seq_num_S_length+Packet_2_1.ACK_length+Packet_2_1.NAK_length]
        checksum_S = byte_S[Packet_2_1.seq_num_S_length+Packet_2_1.seq_num_S_length+Packet_2_1.ACK_length+Packet_2_1.NAK_length :
                            Packet_2_1.seq_num_S_length+Packet_2_1.length_S_length+Packet_2_1.ACK_length+Packet_2_1.NAK_length+Packet_2_1.checksum_length]
        msg_S = byte_S[Packet_2_1.seq_num_S_length+Packet_2_1.seq_num_S_length+Packet_2_1.ACK_length+Packet_2_1.NAK_length+Packet_2_1.checksum_length :]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+ACK_S+NAK_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S

    def isACK(self):
        return self.ACK == 1

    def isNAK(self):
        return self.NAK == 1
        

class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    last_num = 0
    last_message = None
    ## buffer of bytes read from network
    byte_buffer = ''
    
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
            
    def rdt_2_1_send(self, msg_S):
        print("s")
        count = 0
        while True:
            p = Packet_2_1(self.seq_num, 0, 0, msg_S)
            if p is None:
                print("bad")
                break
            self.network.udt_send(p.get_byte_S())
            pkt_rcv = self.network.udt_receive()
            while pkt_rcv is None or len(pkt_rcv) < 54:
                pkt_rcv = self.network.udt_receive()
            length = int(pkt_rcv[0:10])
            packet = Packet_2_1.from_byte_S(pkt_rcv[0:length])
            if packet is not None and packet.isACK():
                print("receive ACK")
                #seq nums are 0,1,0,1...shouldn't have same number 2x in a row
                if self.seq_num == 0:
                    self.seq_num = 1
                else:
                    self.seq_num = 0
                break
            # if sent a msg send NAK and exit function
            elif packet is not None and not packet.isNAK() and packet.msg_S != '' and self.last_message is not None and packet.msg_S in self.last_message:
                print("0")
                count += 1
                pack = Packet_2_1(packet.seq_num, 1, 0, "")
                self.network.udt_send(pack.get_byte_S())
                if count == 10:
                    break
            
  
    def rdt_2_1_receive(self):
        print("r")
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet_2_1.length_S_length):
                sleep(0.1)
                self.last_message = ret_S
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet_2_1.length_S_length])
            if len(self.byte_buffer) < length:
                sleep(0.1)
                self.last_message = ret_S
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet_2_1.from_byte_S(self.byte_buffer[0:length])
            if p is None or p.isACK() or p.isNAK():
                print("1")
                packet = Packet_2_1(0, 0, 1, "")
                self.network.udt_send(packet.get_byte_S())
                #sleep(0.1)
                return None
            elif p.seq_num == self.last_num:
                print("2")
                packet = Packet_2_1(p.seq_num, 1, 0, "")
                self.network.udt_send(packet.get_byte_S())
            elif p.seq_num != self.last_num:
                print("3")
                packet = Packet_2_1(p.seq_num, 1, 0, "")
                self.network.udt_send(packet.get_byte_S())
                ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                self.last_num = p.seq_num
            else:
                print("4")
                packet = Packet_2_1(p.seq_num, 0, 1, "")
                self.network.udt_send(packet.get_byte_S())
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration
        
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
        


        
        
