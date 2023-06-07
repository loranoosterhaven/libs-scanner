#ifndef LIBSINSPECTOR_H
#define LIBSINSPECTOR_H

#include "apk.h"

enum ESupportedLibs {
    LIB_ALIPAY,
    LIB_FIREBASE,
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
    LIB_MILKMAN,
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
};

class CLibsInspector {
public:
    explicit CLibsInspector(CAPK *apk) : apk(apk) { memset(foundLib,0,sizeof(foundLib));}
    bool hasLib( ESupportedLibs libType ) { return foundLib[libType]; }

    void scan();

    static char* getFriendlyName( ESupportedLibs libType );
    static char* getHeaderName( ESupportedLibs libType );

private:
    bool foundLib[LIB_MAX];
    CAPK *apk;
};

#endif //LIBSINSPECTOR_H
