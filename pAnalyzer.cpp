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

int main(int argc, char* argv[]){
  uint32_t framesize;
  ifstream is ("dumpfile.bin", ifstream::binary);
  while(is.read(reinterpret_cast<char *>(&framesize), sizeof(framesize))){
    framesize = ntohl(framesize);
    char *buffer = new char[framesize];
    frame *frame_ptr = reinterpret_cast<frame *>(buffer);
    is.read(buffer, framesize);
    cout << endl;
    cout << "ETHER:\t---- Ether Header ----" << endl;
    cout << "ETHER:" << endl;
    cout << "ETHER:\tPacket " << framecount++ << endl;
    cout << "ETHER:\tPacket size = " << framesize << " bytes" << endl;
    cout << "ETHER:\tDestination = ";
    print_MAC_addr(frame_ptr->MACdestination);
    cout << "ETHER:\tSource = ";
    print_MAC_addr(frame_ptr->MACsource);
    cout << "ETHER:\tEthertype = ";
    string ethertype (printEthertype(frame_ptr->ethertype));
    cout << ethertype << endl;
    cout << "ETHER:" << endl;
    if (ethertype == "(IP)"){
      ip *ip_ptr = reinterpret_cast<ip *>(frame_ptr->payload);
      uint8_t version = ip_ptr->version >> 4;
      uint8_t ihl = (ip_ptr->version & 0x0f) * 32 / 8;
      unsigned char *ip_payload = (reinterpret_cast<unsigned char *>(ip_ptr) + ihl);
      uint8_t dscp = ip_ptr->dscp >> 2;
      uint16_t totLen = ntohs(ip_ptr->totLen);
      uint16_t id = ntohs(ip_ptr->id);
      uint16_t doNotFrag = ntohs(ip_ptr->flags) >> 14;
      uint16_t moreFrag = ntohs(ip_ptr->flags) >> 13 & 1;
      uint16_t fragOffset = ntohs(ip_ptr->flags) & 0x1fff;
      uint8_t proto = ip_ptr->proto;
      uint16_t checksum = ntohs(ip_ptr->checksum);
      uint8_t *IPsource = ip_ptr->IPsource;
      uint8_t *IPdestination = ip_ptr->IPdestination;
      cout << "IP:\t----- IP Header -----" << endl;
      cout << "IP:" << endl;
      cout << "IP:\tVersion = " << unsigned(version) << endl;
      cout << "IP:\tHeader length = " << unsigned(ihl) << " bytes" << endl;
      cout << "IP:\tType of service = " << unsigned(dscp) << endl;
      cout << "IP:\tTotal length = " << unsigned(totLen) << endl;
      cout << "IP:\tIdentification = " << unsigned(id) << endl;
      cout << "IP:\tFlags" << endl;
      cout << "IP:\t\t." << unsigned(doNotFrag) << ".. .... = ";
      if (doNotFrag){
        cout << "do not fragment" << endl;
      }else{
        cout << "allow fragment" << endl;
      }
      cout << "IP:\t\t.." << unsigned(moreFrag) << ". .... = ";
      if (moreFrag){
        cout << "more fragment" << endl;
      }else{
        cout << "last fragment" << endl;
      }
      cout << "IP:\tFragment offset = " << unsigned(fragOffset) << endl;
      cout << "IP:\tProtocol = " << unsigned(proto) << " ";
      switch (proto){
        case 1 :
          cout << "(ICMP)" << endl;
          ++icmp_count;
          break;
        case 6 :
          cout << "(TCP)" << endl;
          ++tcp_count;
          break;
        case 17 :
          cout << "(UDP)" << endl;
          ++udp_count;
          break;
        default :
          cout << "(unkown)" << endl;
          ++other_ip_count;
      }
      cout << "IP:\tHeader checksum = " << hex << checksum << endl << dec;
      cout << "IP:\tSource address = ";
      for (int i = 0; i < 4; ++i, ++IPsource){
        cout << unsigned(*IPsource);
        if (i != 3){
          cout << ".";
        }
      }
      cout << endl;
      cout << "IP:\tDestination address = ";
      for (int i = 0; i < 4; ++i, ++IPdestination){
        cout << unsigned(*IPdestination);
        if (i != 3){
          cout << ".";
        }
      }
      cout << endl;
      if (ihl > 20){
        cout << "IP:\tOptions ignored" << endl;
      }else{
        cout << "IP:\tNo options" << endl;
      }
      cout << "IP:" << endl;
      switch (proto){
        case 1 :
          cout << "ICMP:\t----- ICMP Header -----" << endl;

          break;
        case 6 : {
          tcp *tcp_ptr = reinterpret_cast<tcp *>(ip_payload);
          uint16_t source = ntohs(tcp_ptr->source);
          uint16_t destination = ntohs(tcp_ptr->destination);
          uint32_t sequence = ntohl(tcp_ptr->sequence);
          uint32_t ack = ntohl(tcp_ptr->ack);
          uint8_t dataOffset = (tcp_ptr->dataOffset & 0xf0) * 32 / 8;
          bool URG = tcp_ptr->flags & 0x20;
          bool ACK = tcp_ptr->flags & 0x10;
          bool PSH = tcp_ptr->flags & 0x08;
          bool RST = tcp_ptr->flags & 0x04;
          bool SYN = tcp_ptr->flags & 0x02;
          bool FIN = tcp_ptr->flags & 0x01;
          uint16_t window = ntohs(tcp_ptr->window);
          uint16_t checksum = ntohs(tcp_ptr->checksum);
          uint16_t urgentPtr = ntohs(tcp_ptr->urgentPtr);
          cout << "TCP:\t----- TCP Header -----" << endl;
          cout << "TCP:" << endl;
          cout << "TCP:\tSource port = " << unsigned(source) << endl;
          cout << "TCP:\tDestination port = " << unsigned(destination) << endl;
          cout << "TCP:\tSequence number = " << unsigned(sequence) << endl;
          cout << "TCP:\tAcknowledgement number = " << unsigned(ack) << endl;
          cout << "TCP:\tData offset = " << unsigned(dataOffset) << " bytes" << endl;
          cout << "TCP:\tFlags" << endl;
          cout << "TCP:\t\t.." << URG << ". .... = ";
          if (URG){
            cout << "Urgent pointer" << endl;
          }else{
            cout << "No urgent pointer" << endl;
          }
          cout << "TCP:\t\t..." << ACK << " .... = ";
          if (ACK){
            cout << "Acknowledgement" << endl;
          }else{
            cout << "No acknowledgement" << endl;
          }
          cout << "TCP:\t\t.... " << PSH << "... = ";
          if (PSH){
            cout << "Push" << endl;
          }else{
            cout << "No push" << endl;
          }
          cout << "TCP:\t\t.... ." << RST << ".. = ";
          if (RST){
            cout << "Reset" << endl;
          }else{
            cout << "No reset" << endl;
          }
          cout << "TCP:\t\t.... .." << SYN << ". = ";
          if (SYN){
            cout << "Syn" << endl;
          }else{
            cout << "No syn" << endl;
          }
          cout << "TCP:\t\t.... ..." << FIN << " = ";
          if (FIN){
            cout << "Fin" << endl;
          }else{
            cout << "No fin" << endl;
          }
          cout << "TCP:\tWindow = " << unsigned(window) << endl;
          cout << "TCP:\tChecksum = " << hex << checksum << endl << dec;
          cout << "TCP:\tUrgent pointer = " << unsigned(urgentPtr) << endl;
          cout << "TCP:\t";
          if (dataOffset > 20){
            cout << "Options ignored" << endl;
          }else{
            cout << "No options" << endl;
          }
          cout << "TCP:" << endl;
          break;
          }

        case 17 :
          cout << "UDP:\t----- UDP Header -----" << endl;
      }
    }else if (ethertype == "(ARP)"){
      cout << "DO ARP STUFF" << endl;
    }
    delete[] buffer;
    buffer = NULL;
  }
  cout << "framecount: " << framecount << endl;
  return 0;
}


void print_MAC_addr(const char * ptr){
  char mystr[18];
  char tempstr[3];
  mystr[17] = '\0';
  for (int i = 0; i < 6; ++i, ++ptr){
    snprintf(tempstr, 3, "%x", (int)(*(unsigned char*)(ptr)));
    strncat(mystr,tempstr,2);
    if (i !=5 ){
      strncat(mystr,":",1);
    }
  }
  puts(mystr);
  if (strcmp(mystr,"ff:ff:ff:ff:ff:ff") == 0){
    ++broadcast_count;
  }
}

string printEthertype(uint16_t ethertype){
  string returnStr;
  ethertype = ntohs(ethertype);
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
      returnStr = "(unkown)";
      ++other_count;
  }
  cout << dec;
  return returnStr;
}
