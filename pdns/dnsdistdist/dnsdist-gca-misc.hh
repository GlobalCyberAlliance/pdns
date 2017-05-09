

class DNSDistGcaMisc
{
public:

static void print_buf(const char *title, const unsigned char *buf, size_t buf_len);
static std::string  convertName(const unsigned char *strIn);
static u_char* ReadName(unsigned char* reader, unsigned char* buffer, int* count);
static int dumpDNSAnswer(const std::string &value, uint16_t len);
static int dumpDNS(const unsigned char *value, uint16_t len);
};
