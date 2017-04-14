
#include "dnsdist.hh"
#include "dnsdist-gca-misc.hh"




#define T_A 1           /* Ipv4 address */
#define T_NS 2          /* Nameserver */
#define T_CNAME 5       /* canonical name */
#define T_SOA 6         /* start of authority zone */
#define T_PTR 12        /* domain name pointer */
#define T_MX 15         /* Mail server */

struct DNS_HEADER
{                               //DNS header structure
    unsigned short id;          // identification number

    unsigned char rd :1;        // recursion desired
    unsigned char tc :1;        // truncated message
    unsigned char aa :1;        // authoritive answer
    unsigned char opcode :4;    // purpose of message
    unsigned char qr :1;        // query/response flag

    unsigned char rcode :4;     // response code
    unsigned char cd :1;        // checking disabled
    unsigned char ad :1;        // authenticated data
    unsigned char z :1;         // its z! reserved
    unsigned char ra :1;        // recursion available

    unsigned short q_count;     // number of question entries
    unsigned short ans_count;   // number of answer entries
    unsigned short auth_count;  // number of authority entries
    unsigned short add_count;   // number of resource entries
};


struct QUESTION
{                               // Constant sized fields of query structure
    unsigned short qtype;
    unsigned short qclass;
};

                                // Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

                                // Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

                                // Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;


//------------------------------------------------------------------------------
// convertName() - convert 3www6google3com0 to www.google.com
//                 outputs this as a string....
//------------------------------------------------------------------------------
std::string  DNSDistGcaMisc::convertName(const unsigned char *strIn)
{
int ii;
int jj;
int p;
std::string strOut;

    int iLen = (int) strlen((const char *)strIn);
    for(ii=0; ii < iLen; ii++)
       {
        p= *(strIn + ii);                 // get length of segment
        for(jj=0; jj < p; jj++)
           {
            strOut += *(strIn + ii + 1);
            ii++;
           }
        if(ii < (iLen - 1))
          {
           strOut += '.';
          }
       }
    return(strOut);
}

//------------------------------------------------------------------------------
// ReadName() - reader - pts to location to start reading
//              buf    - points to the entire dns response
//              count  -
//              returns text in malloc'ed memory
//------------------------------------------------------------------------------
u_char*  DNSDistGcaMisc::ReadName(unsigned char* reader, unsigned char* buffer, int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;

    *count = 1;
    name = (unsigned char*)malloc(256);

    name[0] = '\0';

                                 // read the names in 3www6google3com format
    while(*reader!=0)
      {
        if(*reader>=192)
          {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1;          // we have jumped to another location so counting wont go up!
          }
        else
          {
            name[p++]=*reader;
          }

        reader = reader+1;

        if(jumped==0)
        {
            *count = *count + 1; // if we havent jumped to another location then we can count up
        }
    }

    name[p] = '\0';              // string complete
    if(jumped==1)
      {
        *count = *count + 1;     // number of steps we actually moved forward in the packet
      }

                                 // now convert 3www6google3com0 to www.google.com
    for(i=0; i < (int)strlen((const char*)name); i++)
       {
        p=name[i];
        for(j=0; j < (int)p; j++)
        {
            name[i]  =name[i+1];
            i = i + 1;
        }
        name[i] = '.';
       }
    name[i-1] = '\0';            // remove the last dot
    return name;
}

//------------------------------------------------------------------------------
// dumpDNSAnswer() - dump the dns answer from the cache
//------------------------------------------------------------------------------
int  DNSDistGcaMisc::dumpDNSAnswer(const std::string &value, uint16_t len)
{
int iStatus = 0;


      struct DNS_HEADER *dns = NULL;
      dns = (struct DNS_HEADER*) value.c_str();




//Start reading answers
    int stop=0;
    struct sockaddr_in a;
    int i, j;
    struct RES_RECORD answers[20];
    struct RES_RECORD auth[20];
    struct RES_RECORD addit[20];        // the replies from the DNS server
//    unsigned char buf[65536];
    unsigned char *buf;                 // pts to the start of the dns query / response area
    unsigned char *qname;               // pts to the query portion - after the dns header
    unsigned char *reader;              // pts to the response portion - after dns header & query field

            //point to the query portion
//      qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
            //move ahead of the dns header and the query field
//      reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

      buf = (unsigned char *) value.c_str();             // buf pts to the start of the dns query / response area

      qname = (unsigned char*) value.c_str();            // query pts to the query portion
      qname += sizeof(struct DNS_HEADER);                //

      reader = (unsigned char*) value.c_str();           // reader pts to past the dns header and the query field
      reader += sizeof(struct DNS_HEADER);               //
      reader += (strlen((const char*)qname)+1);          //
      reader += sizeof(struct QUESTION);                 //

      printf("\n");
      std::string strQname = convertName(qname);         // print out the DNS header
      printf("Qname....: %s \n", strQname.c_str());
      printf("ID.......: %d \n",  ntohs(dns->id));
      printf("RD.......: %s   (Recursion) \n", dns->rd?"Yes":"No ");
      printf("TC.......: %s   (Trucated) \n", dns->tc?"Yes":"No ");
      printf("AA.......: %s   (Auth Ans) \n", dns->aa?"Yes":"No ");
      printf("Opcode...: %X \n", dns->opcode);
      printf("QR.......: %s \n", dns->qr?"Yes":"No ");
      printf("Resp code: %X \n", dns->rcode);
      printf("CD.......: %s   (Chk disab) \n", dns->cd?"Yes":"No ");
      printf("AD.......: %s   (Auth data) \n", dns->ad?"Yes":"No ");
      printf("Z........: %s \n", dns->z?"Yes":"No ");
      printf("RA.......: %s   (Recur Avl) \n", dns->ra?"Yes":"No ");

      printf("\nThe response contains : ");
      printf("\n %d Questions.",ntohs(dns->q_count));
      printf("\n %d Answers.",ntohs(dns->ans_count));
      printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
      printf("\n %d Additional records.\n\n",ntohs(dns->add_count));


    for(i=0;i<ntohs(dns->ans_count);i++)
    {                                            // read answers
        answers[i].name=ReadName(reader,buf,&stop);
        reader = reader + stop;

        answers[i].resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);

        if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

            for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
            {
                answers[i].rdata[j]=reader[j];
            }

            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = ReadName(reader,buf,&stop);
            reader = reader + stop;
        }
    }

                                                 // read authorities
    for(i=0;i<ntohs(dns->auth_count);i++)
    {
        auth[i].name=ReadName(reader,buf,&stop);
        reader+=stop;

        auth[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);

        auth[i].rdata=ReadName(reader,buf,&stop);
        reader+=stop;
    }

                                                 // read additional
    for(i=0;i<ntohs(dns->add_count);i++)
    {
        addit[i].name=ReadName(reader,buf,&stop);
        reader+=stop;

        addit[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);

        if(ntohs(addit[i].resource->type)==1)
        {
            addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
            for(j=0;j<ntohs(addit[i].resource->data_len);j++)
            addit[i].rdata[j]=reader[j];

            addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
            reader+=ntohs(addit[i].resource->data_len);
        }
        else
        {
            addit[i].rdata=ReadName(reader,buf,&stop);
            reader+=stop;
        }
    }

                                                     // print answers
    printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
    for(i=0 ; i < ntohs(dns->ans_count) ; i++)
       {
        printf("Name: %s ",answers[i].name);

//        printf("DEBUG -> Resource type: %X   T_A: %X \n", ntohs(answers[i].resource->type), T_A);   // DEBUG
        if( ntohs(answers[i].resource->type) == T_A) // IPv4 address
          {
            long *p;
            p=(long*)answers[i].rdata;
            a.sin_addr.s_addr=(*p);                  // working without ntohl
            printf("has IPv4 address: %s",inet_ntoa(a.sin_addr));
          }

        if(ntohs(answers[i].resource->type)==5)
          {
                                                     // Canonical name for an alias
            printf("has alias name: %s",answers[i].rdata);
          }

        printf("\n");
       }

                                                     // print authorities
    printf("\nAuthoritive Records : %d \n" , ntohs(dns->auth_count) );
    for( i=0 ; i < ntohs(dns->auth_count) ; i++)
       {

        printf("Name : %s ",auth[i].name);
        if(ntohs(auth[i].resource->type)==2)
          {
            printf("has nameserver: %s",auth[i].rdata);
          }
        printf("\n");
       }

                                                     // print additional resource records
    printf("\nAdditional Records: %d \n" , ntohs(dns->add_count) );
    for(i=0; i < ntohs(dns->add_count) ; i++)
       {
        printf("Name: %s ",addit[i].name);
        if(ntohs(addit[i].resource->type)==1)
          {
            long *p;
            p=(long*)addit[i].rdata;
            a.sin_addr.s_addr=(*p);
            printf("has IPv4 address: %s",inet_ntoa(a.sin_addr));
          }
        printf("\n");
       }

    return(iStatus);
}


