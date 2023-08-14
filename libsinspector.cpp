#include <iostream>

#include "dex.h"
#include "libsinspector.h"

char* headerNames[] = {
        "alipay",
        "firebase_analytics",
        "google_mobile_ads",
        "facebook",
        "twitter",
        "unity_ads",
        "amazon_iap",
        "android_vending",
        "authorize_net",
        "bitcoinj",
        "braintree",
        "cardinal_commerce",
        "revenuecat",
        "fortumo",
        "google_play_billing",
        "kin",
        "payanywhere",
        "paypal",
        "robotmedia",
        "samsung_pay",
        "square",
        "stellar",
        "stripe",
        "urban_airship",
};

char* versionHeaderNames[] = {
        "alipay_ver",
        "firebase_analytics_ver",
        "google_mobile_ads_ver",
        "facebook_ver",
        "twitter_ver",
        "unity_ads_ver",
        "amazon_iap_ver",
        "android_vending_ver",
        "authorize_net_ver",
        "bitcoinj_ver",
        "braintree_ver",
        "cardinal_commerce_ver",
        "revenuecat_ver",
        "fortumo_ver",
        "google_play_billing_ver",
        "kin_ver",
        "payanywhere_ver",
        "paypal_ver",
        "robotmedia_ver",
        "samsung_pay_ver",
        "square_ver",
        "stellar_ver",
        "stripe_ver",
        "urban_airship_ver",
};

char* friendlyNames[] = {
        "AliPay",
        "Firebase Analytics",
        "Google Mobile Ads",
        "Facebook",
        "Twitter",
        "Unity Ads",
        "Amazon IAP",
        "Android Vending",
        "Authorize.net",
        "bitcoinj",
        "Braintree",
        "Cardinal Commerce",
        "RevenueCat",
        "Fortumo",
        "Google Play Billing",
        "kin",
        "PayAnywhere",
        "PayPal",
        "Robotmedia",
        "Samsung Pay",
        "Square",
        "Stellar",
        "Stripe",
        "Urban Airship",
};

CStrPattern strPatterns[] = {
    // Alipay done. Needs version?
    { "APPSecuritySDK-ALIPAYSDK", LIB_ALIPAY, false },
    {"&pay_channel_id=\"alipay_sdk\"", LIB_ALIPAY, false },
    {"com.alipay.android", LIB_ALIPAY, true },

    // Firebase done. Needs version?
    {"Invalid google_app_id. Firebase Analytics disabled.", LIB_FIREBASE, false },
    {"Invalid admob_app_id. Analytics disabled.", LIB_FIREBASE, false },

    // Google Mobile Ads done. Needs version?
    {"Mobile ads is initialized already.", LIB_GOOGLE_MOBILE_ADS, false },

    //Needs proper string.
    {"com.facebook.android", LIB_FACEBOOK, true },
    {"Facebook App ID cannot be determined", LIB_FACEBOOK, false },
    {"Facebook-Util", LIB_FACEBOOK, false },
    {"Ad not loaded. First call loadAd()", LIB_FACEBOOK, false },

    //Needs proper string.
    {"TwitterApi", LIB_TWITTER, true},

    // Unity Ads done. Needs version?
    {"The current device is not supported by Unity Ads", LIB_UNITY_ADS, false},
    {"Webapp timeout, shutting down Unity Ads", LIB_UNITY_ADS, false},

    // Amazon IAP done. Was outdated. Is there a version?
    {"Amazon Appstore required", LIB_AMAZON_IAP, false },
    {"com.amazon.device.iap", LIB_AMAZON_IAP, true },
    {"com.amazon.testclient.iap", LIB_AMAZON_IAP, true },
    {"In App Purchasing SDK - ", LIB_AMAZON_IAP, false },

    // Needs checking properly to much hits
    {"com.android.vending.billing.InAppBillingService.BIND", LIB_ANDROID_VENDING, false },

    // Authorize.net done. Needs version?
    {"https://api.authorize.net/", LIB_AUTHORIZE_NET, false },
    {"https://apitest.authorize.net/", LIB_AUTHORIZE_NET, false },
    {"net.authorize.action", LIB_AUTHORIZE_NET, true},
    {"net.authorize.extra", LIB_AUTHORIZE_NET, true},

    // Bitcoinj done. Needs version?
    {"org/bitcoinj/core/", LIB_BITCOINJ, true},
    {"org.bitcoinj.wallet", LIB_BITCOINJ, true},
    {"org.bitcoinj.unittest", LIB_BITCOINJ, true},
    {"/bitcoinj:", LIB_BITCOINJ, false}, //Contains version
    {"Performing thread fixup: you are accessing bitcoinj via a thread that has not had any context set on it", LIB_BITCOINJ, false},
    {"You must construct a Context object before using bitcoinj!", LIB_BITCOINJ, false},

    // NEEDS STRING NOT VULNERABLE FOR OBFUSCATION
    {"Braintree-Version", LIB_BRAINTREE, false},
    {"BraintreeError for ", LIB_BRAINTREE, false},
    {"braintree/android/", LIB_BRAINTREE, false}, // can be used to obtain version
    {"https://api.braintreegateway.com/", LIB_BRAINTREE, false},
    {"BraintreePaymentActivity", LIB_BRAINTREE, true},
    {"com.braintreepayments.api", LIB_BRAINTREE, true},

    // Cardinal done. Needs version?
    {"com/cardinalcommerce/cardinalmobilesdk/", LIB_CARDINALCOMMERCE, true},
    {"com.cardinalcommerce.dependencies", LIB_CARDINALCOMMERCE, true},
    {"Cardinal Challenge Failed", LIB_CARDINALCOMMERCE, false},
    {"An error occurred during Cardinal", LIB_CARDINALCOMMERCE, false},
    {"Cardinal Fingerprint failed", LIB_CARDINALCOMMERCE, false},
    {"three-d-secure.cardinal-sdk.init.setup-completed", LIB_CARDINALCOMMERCE, false},

    // NO HITS NEEDS CHECKING FROM ONLINE SRC
    {"com.revenuecat.purchases",LIB_REVENUECAT, true},
    {"https://api.revenuecat.com/",LIB_REVENUECAT, false},
    {"null cannot be cast to non-null type com.revenuecat.purchases.PurchaserInfo",LIB_REVENUECAT, false},
    {"com/revenuecat/purchases/Package;",LIB_REVENUECAT, true},
    {"Purchases is being configured using a proxy for RevenueCat",LIB_REVENUECAT, false},

    // Should work but n=1 so needs to check other dataset.
    { "com/fortumo/",LIB_FORTUMO, true},
    {"com.fortumo.android.key",LIB_FORTUMO, true},
    {"parsed xml is not valid fortumo xml",LIB_FORTUMO, false},
    {"Fortumo in-app library",LIB_FORTUMO, false},

    // Google Play Billig done. Needs version?
    {"playBillingLibraryVersion",LIB_GOOGLE_PLAY_BILLING, false},
    {"Launching Play Store billing flow",LIB_GOOGLE_PLAY_BILLING, false},
    {" and billing's responseCode: ",LIB_GOOGLE_PLAY_BILLING, false},

    // NEEDS CHECKING MISSING 2
    {"kin/sdk/",LIB_KIN, true},
    {"com.kin.ecosystem.sdk",LIB_KIN, true},
    {"Not enough kin to perform the transaction",LIB_KIN, false},
    {"kin_balance_updated",LIB_KIN, false},
    {"kin.backup",LIB_KIN, true},

    // NEEDS CHCKING MISSES HIT
    {"com/nabancard/payanywheresdk/",LIB_PAYANYWHERE, true},
    {"com.nabancard.payanywheresdk",LIB_PAYANYWHERE, true},
    {"Getting PayAnywhere Info...",LIB_PAYANYWHERE, false},
    {"Getting PayAnywhere info failed",LIB_PAYANYWHERE, false},

    // NEEDS EXTRA STRING
   {"Missing EXTRA_PAYPAL_CONFIGURATION. To avoid this error, set EXTRA_PAYPAL_CONFIGURATION in both PayPalService, and the initializing activity.",LIB_PAYPAL, false},
   {"paypal.sdk",LIB_PAYPAL, false},
   {"com.paypal.android",LIB_PAYPAL, true},
    {"https://api-m.paypal.com/v1/",LIB_PAYPAL, false},

   // Robotmedia done. Needs version?
   {"Remote billing service crashed",LIB_ROBOTMEDIA},
    {"Could not bind to MarketBillingService",LIB_ROBOTMEDIA},

   // Samsung Pay done. Needs version?
   {"Samsung Pay Service",LIB_SAMSUNG_PAY, false},
   {"Samsung Account Result : ",LIB_SAMSUNG_PAY, false},

    // Square NOT done. Add META strings.
   {"Square Point of Sale is not installed on this device.",LIB_SQUARE, false},
    {"Square Reader",LIB_SQUARE, false},
   { "Please contact Square developer support via http://squareup.com/help/contact",LIB_SQUARE, false},
   {"Square Support Center",LIB_SQUARE, false},

    // Stellar done. Needs version?
   {"org/stellar",LIB_STELLAR, false},
   {"org.stellar.sdk",LIB_STELLAR, true},
   { "Public Global Stellar Network",LIB_STELLAR, false},
   {"stellar_kin_trustline_setup_failed",LIB_STELLAR, false},
   {"stellar_account_creation_requested",LIB_STELLAR, false},

   // Stripe done. Needs version?
   { "https://stripe.com/docs/stripe.js",LIB_STRIPE, false},
   { "X-Stripe-Client-User-Agent",LIB_STRIPE, false},
   { "Stripe-",LIB_STRIPE, false},
   {"stripe-android/",LIB_STRIPE, false},

   // 1 HIT, NEEDS CHECKING
   { "AirshipConfigOptions",LIB_URBAN_AIRSHIP, false},
   { "Unable to resolve UrbanAirshipProvider.",LIB_URBAN_AIRSHIP, false},
};

void CLibsInspector::scan() {
    for( int i = 0; i < apk->getNumDex(); i++ ) {
        CDex* targetDex = apk->getDex(i);
        for ( int j = 0; j < targetDex->getNumStrings(); j++ ) {
            char* targetStr = targetDex->getString(j);
            for (auto & strPattern : strPatterns) {
                if (strstr(targetStr, strPattern.substr) != nullptr) {
                    foundLib[strPattern.targetLib] = true;

                    if(!strPattern.isMetaStr) {
                        nonMetaMatch[strPattern.targetLib] = true;
                    }
                }
            }
        }
    }

    scanVersions();
}

void CLibsInspector::scanVersions()
{
    if(foundLib[LIB_STRIPE]) {
        scanStripeVersion();
    } else if(foundLib[LIB_BRAINTREE]) {
        scanBraintreeVersion();
    }
}

void CLibsInspector::scanBraintreeVersion()
{
    for( int i = 0; i < apk->getNumDex(); i++ ) {
        CDex* targetDex = apk->getDex(i);
        for ( int j = 0; j < targetDex->getNumStrings(); j++ ) {
            char* targetStr = targetDex->getString(j);

            if (strstr(targetStr, "braintree/android/") != nullptr || strstr(targetStr, "braintree/core/") == targetStr) {
                char* versionSubstr = strchr(targetStr,'/');

                if( versionSubstr != nullptr) {
                    versionSubstr = strchr(versionSubstr + 1,'/');
                }
                if( versionSubstr != nullptr ) {
                    versionSubstr++;
                    strcpy(libVersions[LIB_BRAINTREE], versionSubstr);
                }
            }
        }
    }
}

void CLibsInspector::scanStripeVersion()
{
    for( int i = 0; i < apk->getNumDex(); i++ ) {
        CDex* targetDex = apk->getDex(i);
        for ( int j = 0; j < targetDex->getNumStrings(); j++ ) {
            char* targetStr = targetDex->getString(j);

            if (strstr(targetStr, "stripe-android/") != nullptr || strstr(targetStr, "AndroidBindings/") == targetStr) {
                char* versionSubstr = strchr(targetStr,'/');

                if( versionSubstr != nullptr ) {
                    versionSubstr++;
                    strcpy(libVersions[LIB_STRIPE], versionSubstr);
                }
            }
        }
    }
}

char* CLibsInspector::getFriendlyName(ESupportedLibs libType) {
    return friendlyNames[libType];
}

char* CLibsInspector::getHeaderName(ESupportedLibs libType) {
    return headerNames[libType];
}

char* CLibsInspector::getVersionHeaderName(ESupportedLibs libType) {
    return versionHeaderNames[libType];
}

char* CLibsInspector::getVersion( ESupportedLibs libType ) {
    return libVersions[libType];
}
