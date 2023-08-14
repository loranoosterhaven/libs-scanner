#ifndef LIBSINSPECTOR_H
#define LIBSINSPECTOR_H

#include "apk.h"

enum ESupportedLibs {
    LIB_ALIPAY,
    LIB_FIREBASE,
    LIB_GOOGLE_MOBILE_ADS,
    LIB_FACEBOOK,
    LIB_TWITTER,
    LIB_UNITY_ADS,
    LIB_AMAZON_IAP,
    LIB_ANDROID_VENDING,
    LIB_AUTHORIZE_NET,
    LIB_BITCOINJ,
    LIB_BRAINTREE,
    LIB_CARDINALCOMMERCE,
    LIB_REVENUECAT,
    LIB_FORTUMO,
    LIB_GOOGLE_PLAY_BILLING,
    LIB_KIN,
    LIB_PAYANYWHERE,
    LIB_PAYPAL,
    LIB_ROBOTMEDIA,
    LIB_SAMSUNG_PAY,
    LIB_SQUARE,
    LIB_STELLAR,
    LIB_STRIPE,
    LIB_URBAN_AIRSHIP,
    LIB_MAX,
};

class CStrPattern {
public:
    char* substr;
    ESupportedLibs targetLib;
    bool isMetaStr;
};

class CLibsInspector {
public:
    explicit CLibsInspector(CAPK *apk) : apk(apk)
    {
        memset(foundLib,0,sizeof(foundLib));
        memset(nonMetaMatch,0,sizeof(nonMetaMatch));
        memset(libVersions,0,sizeof(libVersions));
    }
    bool hasLib( ESupportedLibs libType ) { return foundLib[libType]; }
    bool hasNonMetaMatch( ESupportedLibs libType ) { return nonMetaMatch[libType]; }
    void scan();

    static char* getFriendlyName( ESupportedLibs libType );
    static char* getHeaderName( ESupportedLibs libType );
    static char* getVersionHeaderName( ESupportedLibs libType );

    char* getVersion( ESupportedLibs libType );

    CAPK* getAPK() { return apk; }

private:
    void scanVersions();

    void scanStripeVersion();
    void scanBraintreeVersion();

private:
    bool foundLib[LIB_MAX];
    bool nonMetaMatch[LIB_MAX];
    char libVersions[LIB_MAX][128];

    CAPK *apk;
};

#endif //LIBSINSPECTOR_H
