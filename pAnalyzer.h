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

struct tcp{
  uint16_t source;
  uint16_t destination;
  uint32_t sequence;
  uint32_t ack;
  uint8_t dataOffset;
  uint8_t flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgentPtr;
};

struct icmp{
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t id;
  uint16_t sequence;
};

struct udp{
  uint16_t source;
  uint16_t destination;
  uint16_t length;
  uint16_t checksum;
};

//Ethernet Frame
struct frame{
  char MACdestination[6];
  char MACsource[6];
  uint16_t ethertype;
  uint8_t payload[20];
};

struct arp{
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t operation;
  char sha[6];
  uint8_t spa[4];
  char tha[6];
  uint8_t tpa[4];
};

// Functions
void print_MAC_addr(const char * ptr);
void print_IP_addr(uint8_t *ptr);
std::__cxx11::string printEthertype( uint16_t ethertype );

#endif
