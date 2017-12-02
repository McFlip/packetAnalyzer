#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstdlib>
#include <vector>
#include <cstdint>
#include <arpa/inet.h>
#include "pAnalyzer.h"
using namespace std;


int main(int argc, char* argv[]){
  int framecount = 0;
  uint32_t framesize;
  ifstream is ("dumpfile.bin", ifstream::binary);
  while(is.read(reinterpret_cast<char *>(&framesize), sizeof(framesize))){
    framesize = ntohl(framesize);
    char *buffer = new char[framesize];
    frame *frame_ptr = reinterpret_cast<frame *>(buffer);
    is.read(buffer, framesize);
    cout << "ETHER:\t---- Ether Header ----" << endl;
    cout << "ETHER:" << endl;
    cout << "ETHER:\tPacket " << framecount++ << endl;
    cout << "ETHER:\tPacket size = " << framesize << " bytes" << endl;
    cout << "ETHER:\tDestination = ";
    print_MAC_addr(frame_ptr->MACdestination);
    cout << endl;
    cout << "ETHER:\tSource = ";
    print_MAC_addr(frame_ptr->MACsource);
    cout << endl;
    cout << "ETHER:\tEthertype = ";
    printEthertype(frame_ptr->ethertype);
    cout << endl;
    delete[] buffer;
    buffer = NULL;
  }
  cout << "framecount: " << framecount << endl;
  return 0;
}


void print_MAC_addr(const char * ptr){
  cout << hex;
  for (int i = 0; i < 6; ++i, ++ptr){
    cout << (int)(*(unsigned char*)(ptr));
    if (i !=5 ){
      cout << ":";
    }
  }
  cout << dec;
}

void printEthertype(uint16_t ethertype){
  cout << hex << setfill('0') << setw(4) << ntohs(ethertype);
  cout << dec;
}
