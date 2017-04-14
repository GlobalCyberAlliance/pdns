

class DNSDistGcaMisc
{
public:

static std::string  convertName(const unsigned char *strIn);
static u_char* ReadName(unsigned char* reader, unsigned char* buffer, int* count);
static int dumpDNSAnswer(const std::string &value, uint16_t len);
};
