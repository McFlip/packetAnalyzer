#include <iostream>
#include <fstream>
#include <cstdlib>
#include <vector>
#include <cstdint> //may not need ???
#include <arpa/inet.h>
#include "pAnalyzer.h"
using namespace std;

const int buffsize = 2048;

int main(int argc, char* argv[]){
  int framecount = 0;
  uint32_t framesize;
  ifstream is ("dumpfile.bin", ifstream::binary);
  char *buffer = new char[buffsize];
  while(is.read(reinterpret_cast<char *>(&framesize), sizeof(framesize))){
    buffer[4] = '\0';
//     framesize = atoi(buffer);
    printf("framesize: %d \n", framesize);
//     cout << "framesize: " << framesize  << endl;
    framesize = htonl(framesize);
    cout << "framesize(htonl): " << framesize << endl;
    is.read(buffer, framesize);
    ++framecount;
  }
  cout << "framecount: " << framecount << endl;
  return 0;
}