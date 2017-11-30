#ifndef pAnalyzer
#define pAnalyzer
//structs for use with the packet analyzer

//Ethernet Frame
struct frame{
  char MACdestination[6];
  char MACsource[6];
  char tag[4];
  char ethertype[2];
};

#endif