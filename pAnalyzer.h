#ifndef pAnalyzer
#define pAnalyzer
#include <cstdint>

struct ip{
  uint8_t version;
  uint8_t dscp;
  uint16_t totLen;
  uint16_t id;
  uint16_t flags;
  uint8_t ttl;
  uint8_t proto;
  uint16_t checksum;
  uint8_t IPsource[4];
  uint8_t IPdestination[4];
};

//Ethernet Frame
struct frame{
  char MACdestination[6];
  char MACsource[6];
  uint16_t ethertype;
  uint8_t payload[20];
};

// Functions
void print_MAC_addr(const char * ptr);
std::__cxx11::string printEthertype( uint16_t ethertype );

#endif
