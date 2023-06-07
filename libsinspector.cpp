#include <iostream>

#include "dex.h"
#include "libsinspector.h"

char* headerNames[] = {
        "aliPay",
        "firebase_analytics",
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
        "milkman",
        "payanywhere",
        "paypal",
        "robotmedia",
        "samsung_pay",
        "square",
        "stellar",
        "stripe",
        "urban_airship",
};

char* friendlyNames[] = {
        "AliPay",
        "Firebase Analytics",
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
        "Milkman",
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
    {"APPSecuritySDK-ALIPAYSDK", LIB_ALIPAY },
    {"&pay_channel_id=\"alipay_sdk\"", LIB_ALIPAY },

    {"Invalid google_app_id. Firebase Analytics disabled.", LIB_FIREBASE },
    {"Invalid admob_app_id. Analytics disabled.", LIB_FIREBASE },

    {"Amazon Appstore required", LIB_AMAZON_IAP },
    {"com.amazon.inapp.purchasing", LIB_AMAZON_IAP },

    {"com.android.vending.billing.InAppBillingService.BIND", LIB_ANDROID_VENDING},

    {"/authorize/acceptsdk/", LIB_AUTHORIZE_NET},
    {"net.authorize.action", LIB_AUTHORIZE_NET},
    {"net.authorize.extra", LIB_AUTHORIZE_NET},

    {"org/bitcoinj/core/", LIB_BITCOINJ},
    {"org.bitcoinj.wallet", LIB_BITCOINJ},
    {"org.bitcoinj.unittest", LIB_BITCOINJ},
    {"Performing thread fixup: you are accessing bitcoinj via a thread that has not had any context set on it", LIB_BITCOINJ},

    {"BraintreePaymentActivity", LIB_BRAINTREE},
    {"com.braintreepayments.api", LIB_BRAINTREE},

    {"com/cardinalcommerce/cardinalmobilesdk/", LIB_CARDINALCOMMERCE},
    {"com.cardinalcommerce.dependencies", LIB_CARDINALCOMMERCE},
    {"Cardinal Challenge Failed", LIB_CARDINALCOMMERCE},
    {"An error occurred during Cardinal", LIB_CARDINALCOMMERCE},
    {"Cardinal Fingerprint failed", LIB_CARDINALCOMMERCE},

    {"com.revenuecat.purchases",LIB_REVENUECAT},
    {"https://api.revenuecat.com/",LIB_REVENUECAT},
    {"null cannot be cast to non-null type com.revenuecat.purchases.PurchaserInfo",LIB_REVENUECAT},
    {"com/revenuecat/purchases/Package;",LIB_REVENUECAT},
    {"Purchases is being configured using a proxy for RevenueCat",LIB_REVENUECAT},

    { "com/fortumo/",LIB_FORTUMO},
    {"com.fortumo.android.key",LIB_FORTUMO},
    {"parsed xml is not valid fortumo xml",LIB_FORTUMO},
    {"Fortumo in-app library",LIB_FORTUMO},

    {"playBillingLibraryVersion",LIB_GOOGLE_PLAY_BILLING},
    {"Launching Play Store billing flow",LIB_GOOGLE_PLAY_BILLING},
    {" and billing's responseCode: ",LIB_GOOGLE_PLAY_BILLING},

    {"kin/sdk/",LIB_KIN},
    {"com.kin.ecosystem.sdk",LIB_KIN},
    {"Not enough kin to perform the transaction",LIB_KIN},
    {"kin_balance_updated",LIB_KIN},
    {"kin.backup",LIB_KIN},

    {"com.milkmangames.extensions.android",LIB_MILKMAN},

    {"com/nabancard/payanywheresdk/",LIB_PAYANYWHERE},
    {"com.nabancard.payanywheresdk",LIB_PAYANYWHERE},
    {"Getting PayAnywhere Info...",LIB_PAYANYWHERE},
    {"Getting PayAnywhere info failed",LIB_PAYANYWHERE},

   {"Missing EXTRA_PAYPAL_CONFIGURATION. To avoid this error, set EXTRA_PAYPAL_CONFIGURATION in both PayPalService, and the initializing activity.",LIB_PAYPAL},
   {"paypal.sdk",LIB_PAYPAL},
   {"com.paypal.android",LIB_PAYPAL},

   {"net/robotmedia/billing/",LIB_ROBOTMEDIA},
   {"net.robotmedia.billing.utils",LIB_ROBOTMEDIA},
   {"net.robotmedia.billing.transactionsRestored",LIB_ROBOTMEDIA},

   {"com.samsung.android.iap",LIB_SAMSUNG_PAY},
   {"an_invalid_value_has_been_provided_for_samsung_in_app_purchase",LIB_SAMSUNG_PAY},
   {"com.samsung.android.sdk.samsungpay",LIB_SAMSUNG_PAY},
   {"Samsung Pay Service",LIB_SAMSUNG_PAY},
   {"Samsung Account Result : ",LIB_SAMSUNG_PAY},

   {"com/squareup/util",LIB_SQUARE},
   {"com.squareup.protos",LIB_SQUARE},
   {"Square Point of Sale is not installed on this device.",LIB_SQUARE},
    {"Square Reader",LIB_SQUARE},
   { "Please contact Square developer support via http://squareup.com/help/contact",LIB_SQUARE},
   {"Square Support Center",LIB_SQUARE},

   {"org/stellar",LIB_STELLAR},
   {"org.stellar.sdk",LIB_STELLAR},
   { "Public Global Stellar Network",LIB_STELLAR},
   {"stellar_kin_trustline_setup_failed",LIB_STELLAR},
   {"stellar_account_creation_requested",LIB_STELLAR},

   { "https://stripe.com/docs/stripe.js",LIB_STRIPE},
   { "X-Stripe-Client-User-Agent",LIB_STRIPE},
   { "Stripe-",LIB_STRIPE},
   {"stripe-android/",LIB_STRIPE},

   { "AirshipConfigOptions appears to be obfuscated.",LIB_URBAN_AIRSHIP},
   { "com.urbanairship.push.NOTIFICATION_OPENED",LIB_URBAN_AIRSHIP},
   { "Unable to resolve UrbanAirshipProvider.",LIB_URBAN_AIRSHIP},
};

void CLibsInspector::scan() {
    for( int i = 0; i < apk->getNumDex(); i++ ) {
        CDex* targetDex = apk->getDex(i);
        for ( int j = 0; j < targetDex->getNumStrings(); j++ ) {
            char* targetStr = targetDex->getString(j);
            for (auto & strPattern : strPatterns) {
                if (strstr(targetStr, strPattern.substr) != nullptr) {
                    //std::cout << apk->getName() << ": found \"" << friendlyNames[strPattern.targetLib]
                     //         << "\" by string \"" << targetStr << "\"" << std::endl;
                    foundLib[strPattern.targetLib] = true;
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
