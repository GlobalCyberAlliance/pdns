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
                strFound = "None";
                break;
        case CACHE_MODE::MODE_RPZ:
                strFound = "RPZ";
                break;
        case CACHE_MODE::MODE_ALL:
                strFound = "ALL";
                break;
        default:
                strFound = "????";
                break;
       }
    return(strFound);
}

// ----------------------------------------------------------------------------
int NamedCache::parseCacheModeText(const std::string& strCacheMode)
{
int iMode = CACHE_MODE::MODE_NONE;
std::string strTemp;

    strTemp = toLower(strCacheMode);
    if(strTemp == "none")
      {
       iMode = CACHE_MODE::MODE_NONE;
      }
    if(strTemp == "rpz")
      {
       iMode = CACHE_MODE::MODE_RPZ;
      }
    if(strTemp == "all")
      {
       iMode = CACHE_MODE::MODE_ALL;
      }

    return(iMode);
}

std::string NamedCache::getCacheTypeText(int iType)
{
std::string strFound;

     switch(iType)
       {
        case CACHE_TYPE::TYPE_NONE:
                strFound = "None";
                break;
        case CACHE_TYPE::TYPE_CDB:
                strFound = "CDB";
                break;
        case CACHE_TYPE::TYPE_LRU:
                strFound = "LRU";
                break;
        case CACHE_TYPE::TYPE_MAP:
                strFound = "MAP";
                break;
        default:
                strFound = "????";
                break;
       }
    return(strFound);
}

// ----------------------------------------------------------------------------
int NamedCache::parseCacheTypeText(const std::string& strCacheType)
{
int iType = CACHE_TYPE::TYPE_NONE;
std::string strTemp;

    strTemp = toLower(strCacheType);
    if(strTemp == "none")
      {
       iType = CACHE_TYPE::TYPE_NONE;
      }
    if(strTemp == "cdb")
      {
       iType = CACHE_TYPE::TYPE_CDB;
      }
    if(strTemp == "lru")
      {
       iType = CACHE_TYPE::TYPE_LRU;
      }
    if(strTemp == "map")
      {
       iType = CACHE_TYPE::TYPE_MAP;
      }

    return(iType);
}

