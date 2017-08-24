// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

#include "dnsdist-nc-namedcache.hh"

// ----------------------------------------------------------------------------
NamedCache::NamedCache()
{
//    std::cout << "NamedCache() \n";
}

std::string NamedCache::getFoundText(int iStat)
{
std::string strFound;

     switch(iStat)
       {
        case CACHE_HIT::HIT_CACHE:
                strFound = "Cache";
                break;
        case CACHE_HIT::HIT_CDB:
                strFound = "  Cdb";
                break;
        case CACHE_HIT::HIT_NONE:
                strFound = " None";
                break;
        default:
                strFound = "?????";
                break;
       }
    return(strFound);
}

std::string NamedCache::getCacheModeText(int iMode)
{
std::string strFound;

     switch(iMode)
       {
        case CACHE_MODE::MODE_NONE:
                strFound = "Nothing";
                break;
        case CACHE_MODE::MODE_RPZ:
                strFound = "RPZ";
                break;
        case CACHE_MODE::MODE_ALL:
                strFound = "ALL";
                break;
        default:
                strFound = "?????";
                break;
       }
    return(strFound);
}

std::string NamedCache::getCacheTypeText(int iType)
{
std::string strFound;

     switch(iType)
       {
        case CACHE_TYPE::TYPE_NONE:
                strFound = "Nothing";
                break;
        case CACHE_TYPE::TYPE_LRU:
                strFound = "LRU";
                break;
        case CACHE_TYPE::TYPE_MAP:
                strFound = "MAP";
                break;
        default:
                strFound = "?????";
                break;
       }
    return(strFound);
}
