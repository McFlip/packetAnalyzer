#ifndef pAnalyzer
#define pAnalyzer
#include <cstdint>

//Ethernet Frame
struct frame{
  char MACdestination[6];
  char MACsource[6];
//   char tag[4];
  uint16_t ethertype;
};

// Functions
void print_MAC_addr(const char * ptr);
void printEthertype( uint16_t ethertype );

#endif
