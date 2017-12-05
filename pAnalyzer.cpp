#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstdlib>
#include <vector>
#include <cstdint>
#include <cstring>
#include <string>
#include <arpa/inet.h>
#include "pAnalyzer.h"
using namespace std;

int framecount = 0, arp_count = 0, ip_count = 0, udp_count = 0, broadcast_count = 0,
      tcp_count = 0, icmp_count = 0, other_ip_count = 0, other_count = 0;
bool verbose = true;
bool VERBOSE = false;
bool countOption = false;
int maxFrameCt = 10;

int main(int argc, char* argv[]){
  uint32_t framesize;
  ifstream is ("dumpfile5000.bin", ifstream::binary);
  while(checkFrameCt(maxFrameCt) && is.read(reinterpret_cast<char *>(&framesize), sizeof(framesize))){
    framesize = ntohl(framesize);
    char *buffer = new char[framesize];
    frame *frame_ptr = reinterpret_cast<frame *>(buffer);
    is.read(buffer, framesize);
    if (VERBOSE){
      cout << endl;
      cout << "ETHER:  ----- Ether Header -----" << endl;
      cout << "ETHER:" << endl;
      cout << "ETHER:  Packet " << framecount << endl;
      cout << "ETHER:  Packet size = " << framesize << " bytes" << endl;
      cout << "ETHER:  Destination = ";
    }
    if (!verbose)
      print_MAC_addr(frame_ptr->MACdestination);
    if (VERBOSE){
      cout << endl << "ETHER:  Source      = ";
      print_MAC_addr(frame_ptr->MACsource); cout << endl;
      cout << "ETHER:  Ethertype   = ";
    }
    string ethertype (printEthertype(frame_ptr->ethertype));
    if (VERBOSE){
      cout << ethertype << endl;
      cout << "ETHER:" << endl;
    }
    if (ethertype == "(IP)"){
      ip *ip_ptr = reinterpret_cast<ip *>(frame_ptr->payload);
      uint8_t version = ip_ptr->version >> 4;
      uint8_t ihl = (ip_ptr->version & 0x0f) * 32 / 8;
      unsigned char *ip_payload = (reinterpret_cast<unsigned char *>(ip_ptr) + ihl);
      uint8_t dscp = ip_ptr->dscp;
      uint16_t totLen = ntohs(ip_ptr->totLen);
      uint16_t id = ntohs(ip_ptr->id);
      uint16_t doNotFrag = ntohs(ip_ptr->flags) >> 14;
      uint16_t moreFrag = ntohs(ip_ptr->flags) >> 13 & 1;
      uint16_t fragOffset = ntohs(ip_ptr->flags) & 0x1fff;
      uint8_t proto = ip_ptr->proto;
      uint16_t checksum = ntohs(ip_ptr->checksum);
      uint8_t *IPsource = ip_ptr->IPsource;
      uint8_t *IPdestination = ip_ptr->IPdestination;
      if (VERBOSE){
        cout << "IP:  ----- IP Header -----" << endl;
        cout << "IP:" << endl;
        cout << "IP:  Version = " << unsigned(version) << endl;
        cout << "IP:  Header length = " << unsigned(ihl) << " bytes" << endl;
        cout << "IP:  Type of service = " << hex << unsigned(dscp) << endl << dec;
        cout << "IP:  Total length = " << unsigned(totLen) << " bytes" << endl;
        cout << "IP:  Identification = " << unsigned(id) << endl;
        cout << "IP:  Flags" << endl;
        cout << "IP:    ." << unsigned(doNotFrag) << ".. .... = ";
        if (doNotFrag){
          cout << "do not fragment" << endl;
        }else{
          cout << "allow fragment" << endl;
        }
        cout << "IP:    .." << unsigned(moreFrag) << ". .... = ";
        if (moreFrag){
          cout << "more fragment" << endl;
        }else{
          cout << "last fragment" << endl;
        }
        cout << "IP:  Fragment offset = " << unsigned(fragOffset) << " bytes" << endl;
        cout << "IP:  Protocol = " << unsigned(proto) << " ";
      }
      switch (proto){
        case 1 :
          if (VERBOSE)
            cout << "(ICMP)" << endl;
          ++icmp_count;
          break;
        case 6 :
          if (VERBOSE)
            cout << "(TCP)" << endl;
          ++tcp_count;
          break;
        case 17 :
          if (VERBOSE)
            cout << "(UDP)" << endl;
          ++udp_count;
          break;
        default :
          if (VERBOSE)
            cout << "(unknown)" << endl;
          ++other_ip_count;
      }
      if (VERBOSE || verbose){
        if (VERBOSE){
          cout << "IP:  Header checksum = " << hex << checksum << endl << dec;
          cout << "IP:  Source address = ";
        }
        print_IP_addr(IPsource);
        if (verbose){
          cout << " -> ";
        }else{
          cout << endl;
          cout << "IP:  Destination address = ";
        }
        print_IP_addr(IPdestination);
        if (VERBOSE){
          cout << endl;
          if (ihl > 20){
          cout << "IP:  Options ignored" << endl;
          }else{
            cout << "IP:  No options" << endl;
          }
          cout << "IP:" << endl;
        }
        switch (proto){
          case 1 : {
            icmp *icmp_ptr = reinterpret_cast<icmp *>(ip_payload);
            uint8_t type = icmp_ptr->type;
            uint8_t code = icmp_ptr->code;
            uint16_t checksum = ntohs(icmp_ptr->checksum);
            uint16_t id = ntohs(icmp_ptr->id);
            uint16_t sequence = ntohs(icmp_ptr->sequence);
            if (VERBOSE){
              cout << "ICMP:  ----- ICMP Header -----" << endl;
              cout << "ICMP: " << endl;
              cout << "ICMP: Type = (" << unsigned(type) << ' ';
            }else{
              cout << " (ICMP), ";
            }
            switch (type){
              case 0 :
                cout << "Echo Reply";
                break;
              case 8 :
                cout << "Echo Request";
                break;
              default :
                cout << "unkown type";
            }
            if(verbose){
              cout << " (type=" << unsigned(type)  << ")" << endl;
            }else{
              cout << ')' << endl;
              cout << "ICMP: Code = " << unsigned(code) << endl;
              cout << "ICMP: Checksum = " << hex << checksum << endl << dec;
              cout << "ICMP: Identifier = "  << unsigned(id) << endl;
              cout << "ICMP: Sequence number = " << unsigned(sequence) << endl;
              cout << "ICMP:" << endl;
            }
            break;
          }
          case 6 : {
            tcp *tcp_ptr = reinterpret_cast<tcp *>(ip_payload);
            uint16_t source = ntohs(tcp_ptr->source);
            uint16_t destination = ntohs(tcp_ptr->destination);
            uint32_t sequence = ntohl(tcp_ptr->sequence);
            uint32_t ack = ntohl(tcp_ptr->ack);
            uint8_t dataOffset = (tcp_ptr->dataOffset >> 4) * 32 / 8;
            bool URG = tcp_ptr->flags & 0x20;
            bool ACK = tcp_ptr->flags & 0x10;
            bool PSH = tcp_ptr->flags & 0x08;
            bool RST = tcp_ptr->flags & 0x04;
            bool SYN = tcp_ptr->flags & 0x02;
            bool FIN = tcp_ptr->flags & 0x01;
            uint16_t window = ntohs(tcp_ptr->window);
            uint16_t checksum = ntohs(tcp_ptr->checksum);
            uint16_t urgentPtr = ntohs(tcp_ptr->urgentPtr);
            if (VERBOSE){
              cout << "TCP:  ----- TCP Header -----" << endl;
              cout << "TCP: " << endl;
              cout << "TCP:  Source port = " << unsigned(source) << endl;
              cout << "TCP:  Destination port = " << unsigned(destination) << endl;
              cout << "TCP:  Sequence number = " << unsigned(sequence) << endl;
              cout << "TCP:  Acknowledgement number = " << unsigned(ack) << endl;
              cout << "TCP:  Data offset = " << unsigned(dataOffset) << " bytes" << endl;
              cout << "TCP:  Flags" << endl;
              cout << "TCP:      .." << URG << ". .... = ";
              if (URG){
                cout << "Urgent pointer" << endl;
              }else{
                cout << "No urgent pointer" << endl;
              }
              cout << "TCP:      ..." << ACK << " .... = ";
              if (ACK){
                cout << "Acknowledgement" << endl;
              }else{
                cout << "No acknowledgement" << endl;
              }
              cout << "TCP:      .... " << PSH << "... = ";
              if (PSH){
                cout << "Push" << endl;
              }else{
                cout << "No push" << endl;
              }
              cout << "TCP:      .... ." << RST << ".. = ";
              if (RST){
                cout << "Reset" << endl;
              }else{
                cout << "No reset" << endl;
              }
              cout << "TCP:      .... .." << SYN << ". = ";
              if (SYN){
                cout << "Syn" << endl;
              }else{
                cout << "No Syn" << endl;
              }
              cout << "TCP:      .... ..." << FIN << " = ";
              if (FIN){
                cout << "Fin" << endl;
              }else{
                cout << "No Fin" << endl;
              }
              cout << "TCP:  Window = " << unsigned(window) << endl;
              cout << "TCP:  Checksum = " << hex << checksum << endl << dec;
              cout << "TCP:  Urgent pointer = " << unsigned(urgentPtr) << endl;
              cout << "TCP:  ";
              if (dataOffset > 20){
                cout << "Options ignored" << endl;
              }else{
                cout << "No options" << endl;
              }
              cout << "TCP:" << endl;
              break;
            }else{
              cout << " (TCP) ";
              cout << "sourceport = " << unsigned(source);
              cout << " destport = " << unsigned(destination) << endl;
            }
          }
          case 17 : {
            udp *udp_ptr = reinterpret_cast<udp *>(ip_payload);
            uint16_t source = ntohs(udp_ptr->source);
            uint16_t destination = ntohs(udp_ptr->destination);
            uint16_t length = ntohs(udp_ptr->length);
            uint16_t checksum = ntohs(udp_ptr->checksum);
            cout << "UDP:  ----- UDP Header -----" << endl;
            cout << "UDP: " << endl;
            cout << "UDP:  Source port = " << unsigned(source) << endl;
            cout << "UDP:  Destination port = " << unsigned(destination) << endl;
            cout << "UDP:  Message length = " << unsigned(length) << endl;
            cout << "UDP:  Checksum = " << hex << checksum << endl << dec;
            cout << "UDP:" << endl;
          }
        }
      }
    }else if (ethertype == "(ARP)"){
      arp *arp_ptr = reinterpret_cast<arp *>(frame_ptr->payload);
      uint16_t htype = ntohs(arp_ptr->htype);
      uint8_t hlen = arp_ptr->hlen;
      uint8_t plen = arp_ptr->plen;
      uint16_t operation = ntohs(arp_ptr->operation);
      if (VERBOSE){
        cout << "ARP:  ----- ARP Frame -----" << endl;
        cout << "ARP:  " << endl;
        cout << "ARP:  Hardware type = " << unsigned(htype) << ' ';
        if (htype == 1){
          cout << "(Ethernet)" << endl;
        }else{
          cout << "(other)" << endl;
        }
        cout << "ARP:  Protocol type = ";
        printEthertype(arp_ptr->ptype);
      }
      if (VERBOSE){
        cout << "(IP)" << endl;
        cout << "ARP:  Length of hardware address = " << unsigned(hlen) << " bytes" << endl;
        cout << "ARP:  Length of protocol address = " << unsigned(plen) << " bytes" << endl;
        cout << "ARP:  Opcode " << unsigned(operation) << ' ';
        if (operation == 1){
          cout << "(ARP Request)" << endl;
        }else{
          cout << "(ARP Reply)" << endl;
        }
        cout << "ARP:  Sender's hardware address = ";
        print_MAC_addr(arp_ptr->sha); cout << endl;
        cout << "ARP:  Sender's protocol address = ";
        print_IP_addr(arp_ptr->spa); cout << endl;
        cout << "ARP:  Target hardware address = ";
        if (operation == 1){
          cout << "?" << endl;
        }else{
          print_MAC_addr(arp_ptr->tha); cout << endl;
        }
        cout << "ARP:  Target protocol address = ";
        print_IP_addr(arp_ptr->tpa); cout << endl;
        cout << "ARP:" << endl;
      }
    }else if (verbose){
      union ethertype_u{
        uint16_t myShort;
        struct oct_t{
          uint8_t oct1;
          uint8_t oct2;
        }oct;
      }e_type;
      e_type.myShort = ntohs(frame_ptr->ethertype);
      cout << "unkown packet (";
      print_MAC_addr(frame_ptr->MACdestination); cout << ", ";
      print_MAC_addr(frame_ptr->MACsource); cout << ", ";
      cout << hex << unsigned(e_type.oct.oct2) << ':' << unsigned(e_type.oct.oct1) << ")" << endl << dec;

    }
    ++framecount;
    delete[] buffer;
    buffer = NULL;
  }
  if (!VERBOSE && !verbose){
    cout << "Ethernet frames: \t" << framecount << endl;
    cout << "Ethernet broadcast: \t" << broadcast_count << endl;
    cout << "  ARP packets: \t\t" << arp_count << endl;
    cout << "  IP packets: \t\t" << ip_count << endl;
    cout << "    UDP packets: \t" << udp_count << endl;
    cout << "    TCP packets: \t" << tcp_count << endl;
    cout << "    ICMP packets: \t" << icmp_count << endl;
    cout << "    other IP packets: \t" << other_ip_count << endl;
    cout << "  other packets: \t" << other_count << endl;
  }
  return 0;
}


void print_MAC_addr(const char * ptr){
  char mystr[18];
  char tempstr[3];
  mystr[0] = '\0';
  for (int i = 0; i < 6; ++i, ++ptr){
    snprintf(tempstr, 3, "%x", (int)(*(unsigned char*)(ptr)));
    strncat(mystr,tempstr,2);
    if (i !=5 ){
      strncat(mystr,":",1);
    }
  }
  if (VERBOSE || verbose)
    cout << mystr;
  if (strcmp(mystr,"ff:ff:ff:ff:ff:ff") == 0){
    ++broadcast_count;
  }
}

void print_IP_addr(uint8_t *ptr){
  for (int i = 0; i < 4; ++i, ++ptr){
    cout << unsigned(*ptr);
    if (i != 3){
      cout << ".";
    }
  }
}

string printEthertype(uint16_t ethertype){
  string returnStr;
  ethertype = ntohs(ethertype);
  if (VERBOSE)
    cout << hex << setfill('0') << setw(4) << ethertype << " ";
  switch (ethertype){
    case 0x0800 :
      ++ip_count;
      returnStr = "(IP)";
      break;
    case 0x0806 :
      returnStr = "(ARP)";
      ++arp_count;
      break;
    default :
      returnStr = "(unknown)";
      ++other_count;
  }
  cout << dec;
  return returnStr;
}

bool checkFrameCt(int max){
  if (!countOption){
    return true;
  }else if (framecount < maxFrameCt){
    return true;
  }else{
    return false;
  }
}
