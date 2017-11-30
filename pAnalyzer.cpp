#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstdlib>
#include <vector>
#include <cstdint> //may not need ???
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
//     struct frame *frame_ptr = ( struct frame* )buffer;
    auto *frame_ptr = reinterpret_cast<unsigned char *>(buffer);
    cout << "framesize(ntohl): " << framesize << endl;
    is.read(buffer, framesize);
    ++framecount;
    cout << "ETHER:\tDestination = ";
    for (int i = 0; i < 6; ++i, ++frame_ptr)
      cout << hex << static_cast<unsigned>(*frame_ptr) << ":";
    cout << endl;
//     << frame_ptr->MACdestination << endl;
    delete[] buffer;
    buffer = NULL;
  }
  cout << "framecount: " << framecount << endl;
  return 0;
}