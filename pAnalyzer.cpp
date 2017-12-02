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
        cout << "FUCK! more fragment" << endl;
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
        case 17 : //TEST check if this is dec or hex ???
          cout << "(UDP)" << endl;
          ++udp_count;
          break;
        default :
          cout << "(FUCK! other)" << endl;
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
        cout << "FUCK!  Bitch has options!" << endl;
      }else{
        cout << "IP:\tNo options" << endl;
      }
      cout << "IP:" << endl;

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
