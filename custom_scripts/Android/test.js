function check() {
    var ServiceENC = Java.use("com.vnpay.domino.ServiceENC");
    ServiceENC["eccEncrypt"].implementation = function (plaintext) {
        console.log(`ServiceENC.eccEncrypt is called: plaintext=${plaintext}`);
        let result = this["eccEncrypt"](plaintext);
        console.log(`ServiceENC.eccEncrypt result=${result}`);
        return result;
    };
    // var ServiceENC = Java.use("com.vnpay.domino.ServiceENC");
    ServiceENC["eccProcess"].implementation = function (s2) {
        console.log(`ServiceENC.eccProcess is called: s2=${s2}`);
        let result = this["eccProcess"](s2);
        console.log(`ServiceENC.eccProcess result=${result}`);
        return result;
    };
}







function test() {
    var BaseActivity = Java.use('com.vnpay.ekyc.core.BaseActivity');
    var AppStatusCallback = Java.use('com.vnpay.ekyc.core.BaseActivity$a');

    AppStatusCallback.onR.implementation = function (j) {
        console.log('[*] onR blocked, device check bypassed, code: ' + j);
    };

    AppStatusCallback.onT.implementation = function (j) {
        console.log('[*] onT blocked, device check bypassed, code: ' + j);
    };
    // var SDKSecurity = Java.use("com.vnp.vnpapp.sdksecurity.SDKSecurity");
    // SDKSecurity["pr"].implementation = function (e, k, s2, ek, mk, il) {
    //     console.log(`SDKSecurity.pr is called: e=${e}, k=${k}, s2=${s2}, ek=${ek}, mk=${mk}, il=${il}`);
    //     let result = this["pr"](e, k, s2, ek, mk, il);
    //     console.log(`SDKSecurity.pr result=${result}`);
    //     return result;
    // };
    // // var SDKSecurity = Java.use("com.vnp.vnpapp.sdksecurity.SDKSecurity");
    // SDKSecurity["fr"].implementation = function (d, ek, mk, l, il) {
    //     console.log(`SDKSecurity.fr is called: d=${d}, ek=${ek}, mk=${mk}, l=${l}, il=${il}`);
    //     let result = this["fr"](d, ek, mk, l, il);
    //     console.log(`SDKSecurity.fr result=${result}`);
    //     return result;
    // };
    // // var SDKSecurity = Java.use("com.vnp.vnpapp.sdksecurity.SDKSecurity");
    // SDKSecurity["en"].implementation = function (d, ek, il) {
    //     console.log(`SDKSecurity.en is called: d=${d}, ek=${ek}, il=${il}`);
    //     let result = this["en"](d, ek, il);
    //     console.log(`SDKSecurity.en result=${result}`);
    //     return result;
    // };
    // // var SDKSecurity = Java.use("com.vnp.vnpapp.sdksecurity.SDKSecurity");
    // SDKSecurity["de"].implementation = function (d, ek, il) {
    //     console.log(`SDKSecurity.de is called: d=${d}, ek=${ek}, il=${il}`);
    //     let result = this["de"](d, ek, il);
    //     console.log(`SDKSecurity.de result=${result}`);
    //     return result;
    // };

    // var d = Java.use("com.vnpay.ekyc.utils.d");
    // d["a"].overload('org.json.JSONObject', 'java.lang.String').implementation = function (jSONObject, str) {
    //     console.log(`d.a is called: jSONObject=${jSONObject}, str=${str}`);
    //     let result = this["a"](jSONObject, str);
    //     // console.log(`d.a result=${result}`);
    //     return result;
    // };
}
function bypass_cert_pining_Long() {

    /// -- Generic hook to protect against SSLPeerUnverifiedException -- ///

    // In some cases, with unusual cert pinning approaches, or heavy obfuscation, we can't
    // match the real method & package names. This is a problem! Fortunately, we can still
    // always match built-in types, so here we spot all failures that use the built-in cert
    // error type (notably this includes OkHttp), and after the first failure, we dynamically
    // generate & inject a patch to completely disable the method that threw the error.
    try {
        const UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
        UnverifiedCertError.$init.implementation = function (str) {
            //console.log('  --> Unexpected SSL verification failure, adding dynamic patch...');

            try {
                const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                const exceptionStackIndex = stackTrace.findIndex(stack =>
                    stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException"
                );
                const callingFunctionStack = stackTrace[exceptionStackIndex + 1];

                const className = callingFunctionStack.getClassName();
                const methodName = callingFunctionStack.getMethodName();

                //console.log(`      Thrown by ${className}->${methodName}`);

                const callingClass = Java.use(className);
                const callingMethod = callingClass[methodName];

                if (callingMethod.implementation) return; // Already patched by Frida - skip it

                //console.log('      Attempting to patch automatically...');
                const returnTypeName = callingMethod.returnType.type;

                callingMethod.implementation = function () {
                    //console.log(`  --> Bypassing ${className}->${methodName} (automatic exception patch)`);

                    // This is not a perfect fix! Most unknown cases like this are really just
                    // checkCert(cert) methods though, so doing nothing is perfect, and if we
                    // do need an actual return value then this is probably the best we can do,
                    // and at least we're logging the method name so you can patch it manually:

                    if (returnTypeName === 'void') {
                        return;
                    } else {
                        return null;
                    }
                };

                //console.log(`      [+] ${className}->${methodName} (automatic exception patch)`);
            } catch (e) {
                //console.log('      [ ] Failed to automatically patch failure');
            }

            return this.$init(str);
        };
        //console.log('[+] SSLPeerUnverifiedException auto-patcher');
    } catch (err) {
        //console.log('[ ] SSLPeerUnverifiedException auto-patcher');
    }

    /// -- Specific targeted hooks: -- ///

    // HttpsURLConnection
    try {
        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (hostnameVerifier) {
            //console.log('  --> Bypassing HttpsURLConnection (setDefaultHostnameVerifier)');
            return; // Do nothing, i.e. don't change the hostname verifier
        };
        //console.log('[+] HttpsURLConnection (setDefaultHostnameVerifier)');
    } catch (err) {
        //console.log('[ ] HttpsURLConnection (setDefaultHostnameVerifier)');
    }
    try {
        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setSSLSocketFactory.implementation = function (SSLSocketFactory) {
            //console.log('  --> Bypassing HttpsURLConnection (setSSLSocketFactory)');
            return; // Do nothing, i.e. don't change the SSL socket factory
        };
        //console.log('[+] HttpsURLConnection (setSSLSocketFactory)');
    } catch (err) {
        //console.log('[ ] HttpsURLConnection (setSSLSocketFactory)');
    }
    try {
        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setHostnameVerifier.implementation = function (hostnameVerifier) {
            //console.log('  --> Bypassing HttpsURLConnection (setHostnameVerifier)');
            return; // Do nothing, i.e. don't change the hostname verifier
        };
        //console.log('[+] HttpsURLConnection (setHostnameVerifier)');
    } catch (err) {
        //console.log('[ ] HttpsURLConnection (setHostnameVerifier)');
    }

    // SSLContext
    try {
        const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        const SSLContext = Java.use('javax.net.ssl.SSLContext');

        const TrustManager = Java.registerClass({
            // Implement a custom TrustManager
            name: 'dev.asd.test.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) { },
                checkServerTrusted: function (chain, authType) { },
                getAcceptedIssuers: function () { return []; }
            }
        });

        // Prepare the TrustManager array to pass to SSLContext.init()
        const TrustManagers = [TrustManager.$new()];

        // Get a handle on the init() on the SSLContext class
        const SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
        );

        // Override the init method, specifying the custom TrustManager
        SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {
            //console.log('  --> Bypassing Trustmanager (Android < 7) request');
            SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
        };
        //console.log('[+] SSLContext');
    } catch (err) {
        //console.log('[ ] SSLContext');
    }

    // TrustManagerImpl (Android > 7)
    try {
        const array_list = Java.use("java.util.ArrayList");
        const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

        // This step is notably what defeats the most common case: network security config
        TrustManagerImpl.checkTrustedRecursive.implementation = function (a1, a2, a3, a4, a5, a6) {
            //console.log('  --> Bypassing TrustManagerImpl checkTrusted ');
            return array_list.$new();
        }

        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            //console.log('  --> Bypassing TrustManagerImpl verifyChain: ' + host);
            return untrustedChain;
        };
        //console.log('[+] TrustManagerImpl');
    } catch (err) {
        //console.log('[ ] TrustManagerImpl');
    }

    // OkHTTPv3 (quadruple bypass)
    try {
        // Bypass OkHTTPv3 {1}
        const okhttp3_Activity_1 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_1.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
            //console.log('  --> Bypassing OkHTTPv3 (list): ' + a);
            return;
        };
        //console.log('[+] OkHTTPv3 (list)');
    } catch (err) {
        //console.log('[ ] OkHTTPv3 (list)');
    }
    try {
        // Bypass OkHTTPv3 {2}
        // This method of CertificatePinner.check could be found in some old Android app
        const okhttp3_Activity_2 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_2.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
            //console.log('  --> Bypassing OkHTTPv3 (cert): ' + a);
            return;
        };
        //console.log('[+] OkHTTPv3 (cert)');
    } catch (err) {
        //console.log('[ ] OkHTTPv3 (cert)');
    }
    try {
        // Bypass OkHTTPv3 {3}
        const okhttp3_Activity_3 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_3.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (a, b) {
            //console.log('  --> Bypassing OkHTTPv3 (cert array): ' + a);
            return;
        };
        //console.log('[+] OkHTTPv3 (cert array)');
    } catch (err) {
        //console.log('[ ] OkHTTPv3 (cert array)');
    }
    try {
        // Bypass OkHTTPv3 {4}
        const okhttp3_Activity_4 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_4['check$okhttp'].implementation = function (a, b) {
            //console.log('  --> Bypassing OkHTTPv3 ($okhttp): ' + a);
            return;
        };
        //console.log('[+] OkHTTPv3 ($okhttp)');
    } catch (err) {
        //console.log('[ ] OkHTTPv3 ($okhttp)');
    }

    // Trustkit (triple bypass)
    try {
        // Bypass Trustkit {1}
        const trustkit_Activity_1 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        trustkit_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
            //console.log('  --> Bypassing Trustkit OkHostnameVerifier(SSLSession): ' + a);
            return true;
        };
        //console.log('[+] Trustkit OkHostnameVerifier(SSLSession)');
    } catch (err) {
        //console.log('[ ] Trustkit OkHostnameVerifier(SSLSession)');
    }
    try {
        // Bypass Trustkit {2}
        const trustkit_Activity_2 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        trustkit_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
            //console.log('  --> Bypassing Trustkit OkHostnameVerifier(cert): ' + a);
            return true;
        };
        //console.log('[+] Trustkit OkHostnameVerifier(cert)');
    } catch (err) {
        //console.log('[ ] Trustkit OkHostnameVerifier(cert)');
    }
    try {
        // Bypass Trustkit {3}
        const trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
        trustkit_PinningTrustManager.checkServerTrusted.implementation = function () {
            //console.log('  --> Bypassing Trustkit PinningTrustManager');
        };
        //console.log('[+] Trustkit PinningTrustManager');
    } catch (err) {
        //console.log('[ ] Trustkit PinningTrustManager');
    }

    // Appcelerator Titanium
    try {
        const appcelerator_PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
        appcelerator_PinningTrustManager.checkServerTrusted.implementation = function () {
            //console.log('  --> Bypassing Appcelerator PinningTrustManager');
        };
        //console.log('[+] Appcelerator PinningTrustManager');
    } catch (err) {
        //console.log('[ ] Appcelerator PinningTrustManager');
    }

    // OpenSSLSocketImpl Conscrypt
    try {
        const OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
        OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, JavaObject, authMethod) {
            //console.log('  --> Bypassing OpenSSLSocketImpl Conscrypt');
        };
        //console.log('[+] OpenSSLSocketImpl Conscrypt');
    } catch (err) {
        //console.log('[ ] OpenSSLSocketImpl Conscrypt');
    }

    // OpenSSLEngineSocketImpl Conscrypt
    try {
        const OpenSSLEngineSocketImpl_Activity = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
        OpenSSLEngineSocketImpl_Activity.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function (a, b) {
            //console.log('  --> Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + b);
        };
        //console.log('[+] OpenSSLEngineSocketImpl Conscrypt');
    } catch (err) {
        //console.log('[ ] OpenSSLEngineSocketImpl Conscrypt');
    }

    // OpenSSLSocketImpl Apache Harmony
    try {
        const OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
        OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function (asn1DerEncodedCertificateChain, authMethod) {
            //console.log('  --> Bypassing OpenSSLSocketImpl Apache Harmony');
        };
        //console.log('[+] OpenSSLSocketImpl Apache Harmony');
    } catch (err) {
        //console.log('[ ] OpenSSLSocketImpl Apache Harmony');
    }

    // PhoneGap sslCertificateChecker (https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin)
    try {
        const phonegap_Activity = Java.use('nl.xservices.plugins.sslCertificateChecker');
        phonegap_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (a, b, c) {
            //console.log('  --> Bypassing PhoneGap sslCertificateChecker: ' + a);
            return true;
        };
        //console.log('[+] PhoneGap sslCertificateChecker');
    } catch (err) {
        //console.log('[ ] PhoneGap sslCertificateChecker');
    }

    // IBM MobileFirst pinTrustedCertificatePublicKey (double bypass)
    try {
        // Bypass IBM MobileFirst {1}
        const WLClient_Activity_1 = Java.use('com.worklight.wlclient.api.WLClient');
        WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function (cert) {
            //console.log('  --> Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string): ' + cert);
            return;
        };
        //console.log('[+] IBM MobileFirst pinTrustedCertificatePublicKey (string)');
    } catch (err) {
        //console.log('[ ] IBM MobileFirst pinTrustedCertificatePublicKey (string)');
    }
    try {
        // Bypass IBM MobileFirst {2}
        const WLClient_Activity_2 = Java.use('com.worklight.wlclient.api.WLClient');
        WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function (cert) {
            //console.log('  --> Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string array): ' + cert);
            return;
        };
        //console.log('[+] IBM MobileFirst pinTrustedCertificatePublicKey (string array)');
    } catch (err) {
        //console.log('[ ] IBM MobileFirst pinTrustedCertificatePublicKey (string array)');
    }

    // IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning (quadruple bypass)
    try {
        // Bypass IBM WorkLight {1}
        const worklight_Activity_1 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function (a, b) {
            //console.log('  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket): ' + a);
            return;
        };
        //console.log('[+] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket)');
    } catch (err) {
        //console.log('[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket)');
    }
    try {
        // Bypass IBM WorkLight {2}
        const worklight_Activity_2 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
            //console.log('  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (cert): ' + a);
            return;
        };
        //console.log('[+] IBM WorkLight HostNameVerifierWithCertificatePinning (cert)');
    } catch (err) {
        //console.log('[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (cert)');
    }
    try {
        // Bypass IBM WorkLight {3}
        const worklight_Activity_3 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity_3.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function (a, b) {
            //console.log('  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (string string): ' + a);
            return;
        };
        //console.log('[+] IBM WorkLight HostNameVerifierWithCertificatePinning (string string)');
    } catch (err) {
        //console.log('[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (string string)');
    }
    try {
        // Bypass IBM WorkLight {4}
        const worklight_Activity_4 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity_4.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
            //console.log('  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession): ' + a);
            return true;
        };
        //console.log('[+] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession)');
    } catch (err) {
        //console.log('[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession)');
    }

    // Conscrypt CertPinManager
    try {
        const conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
        conscrypt_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
            //console.log('  --> Bypassing Conscrypt CertPinManager: ' + a);
            return true;
        };
        //console.log('[+] Conscrypt CertPinManager');
    } catch (err) {
        //console.log('[ ] Conscrypt CertPinManager');
    }

    // CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager
    try {
        const cwac_CertPinManager_Activity = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
        cwac_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
            //console.log('  --> Bypassing CWAC-Netsecurity CertPinManager: ' + a);
            return true;
        };
        //console.log('[+] CWAC-Netsecurity CertPinManager');
    } catch (err) {
        //console.log('[ ] CWAC-Netsecurity CertPinManager');
    }

    // Worklight Androidgap WLCertificatePinningPlugin
    try {
        const androidgap_WLCertificatePinningPlugin_Activity = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
        androidgap_WLCertificatePinningPlugin_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (a, b, c) {
            //console.log('  --> Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + a);
            return true;
        };
        //console.log('[+] Worklight Androidgap WLCertificatePinningPlugin');
    } catch (err) {
        //console.log('[ ] Worklight Androidgap WLCertificatePinningPlugin');
    }

    // Netty FingerprintTrustManagerFactory
    try {
        const netty_FingerprintTrustManagerFactory = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
        netty_FingerprintTrustManagerFactory.checkTrusted.implementation = function (type, chain) {
            //console.log('  --> Bypassing Netty FingerprintTrustManagerFactory');
        };
        //console.log('[+] Netty FingerprintTrustManagerFactory');
    } catch (err) {
        //console.log('[ ] Netty FingerprintTrustManagerFactory');
    }

    // Squareup CertificatePinner [OkHTTP<v3] (double bypass)
    try {
        // Bypass Squareup CertificatePinner {1}
        const Squareup_CertificatePinner_Activity_1 = Java.use('com.squareup.okhttp.CertificatePinner');
        Squareup_CertificatePinner_Activity_1.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
            //console.log('  --> Bypassing Squareup CertificatePinner (cert): ' + a);
            return;
        };
        //console.log('[+] Squareup CertificatePinner (cert)');
    } catch (err) {
        //console.log('[ ] Squareup CertificatePinner (cert)');
    }
    try {
        // Bypass Squareup CertificatePinner {2}
        const Squareup_CertificatePinner_Activity_2 = Java.use('com.squareup.okhttp.CertificatePinner');
        Squareup_CertificatePinner_Activity_2.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
            //console.log('  --> Bypassing Squareup CertificatePinner (list): ' + a);
            return;
        };
        //console.log('[+] Squareup CertificatePinner (list)');
    } catch (err) {
        //console.log('[ ] Squareup CertificatePinner (list)');
    }

    // Squareup OkHostnameVerifier [OkHTTP v3] (double bypass)
    try {
        // Bypass Squareup OkHostnameVerifier {1}
        const Squareup_OkHostnameVerifier_Activity_1 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
        Squareup_OkHostnameVerifier_Activity_1.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
            //console.log('  --> Bypassing Squareup OkHostnameVerifier (cert): ' + a);
            return true;
        };
        //console.log('[+] Squareup OkHostnameVerifier (cert)');
    } catch (err) {
        //console.log('[ ] Squareup OkHostnameVerifier (cert)');
    }
    try {
        // Bypass Squareup OkHostnameVerifier {2}
        const Squareup_OkHostnameVerifier_Activity_2 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
        Squareup_OkHostnameVerifier_Activity_2.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
            //console.log('  --> Bypassing Squareup OkHostnameVerifier (SSLSession): ' + a);
            return true;
        };
        //console.log('[+] Squareup OkHostnameVerifier (SSLSession)');
    } catch (err) {
        //console.log('[ ] Squareup OkHostnameVerifier (SSLSession)');
    }

    // Android WebViewClient (double bypass)
    try {
        // Bypass WebViewClient {1} (deprecated from Android 6)
        const AndroidWebViewClient_Activity_1 = Java.use('android.webkit.WebViewClient');
        AndroidWebViewClient_Activity_1.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
            //console.log('  --> Bypassing Android WebViewClient (SslErrorHandler)');
        };
        //console.log('[+] Android WebViewClient (SslErrorHandler)');
    } catch (err) {
        //console.log('[ ] Android WebViewClient (SslErrorHandler)');
    }
    try {
        // Bypass WebViewClient {2}
        const AndroidWebViewClient_Activity_2 = Java.use('android.webkit.WebViewClient');
        AndroidWebViewClient_Activity_2.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function (obj1, obj2, obj3) {
            //console.log('  --> Bypassing Android WebViewClient (WebResourceError)');
        };
        //console.log('[+] Android WebViewClient (WebResourceError)');
    } catch (err) {
        //console.log('[ ] Android WebViewClient (WebResourceError)');
    }

    // Apache Cordova WebViewClient
    try {
        const CordovaWebViewClient_Activity = Java.use('org.apache.cordova.CordovaWebViewClient');
        CordovaWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
            //console.log('  --> Bypassing Apache Cordova WebViewClient');
            obj3.proceed();
        };
    } catch (err) {
        //console.log('[ ] Apache Cordova WebViewClient');
    }

    // Boye AbstractVerifier
    try {
        const boye_AbstractVerifier = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
        boye_AbstractVerifier.verify.implementation = function (host, ssl) {
            //console.log('  --> Bypassing Boye AbstractVerifier: ' + host);
        };
    } catch (err) {
        //console.log('[ ] Boye AbstractVerifier');
    }

    // Appmattus
    try {
        const appmatus_Activity = Java.use('com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor');
        appmatus_Activity['intercept'].implementation = function (a) {
            //console.log('  --> Bypassing Appmattus (Transparency)');
            return a.proceed(a.request());
        };
        //console.log('[+] Appmattus (CertificateTransparencyInterceptor)');
    } catch (err) {
        //console.log('[ ] Appmattus (CertificateTransparencyInterceptor)');
    }

    try {
        const CertificateTransparencyTrustManager = Java.use(
            'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager'
        );
        CertificateTransparencyTrustManager['checkServerTrusted'].overload(
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String'
        ).implementation = function (x509CertificateArr, str) {
            //console.log('  --> Bypassing Appmattus (CertificateTransparencyTrustManager)');
        };
        CertificateTransparencyTrustManager['checkServerTrusted'].overload(
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String',
            'java.lang.String'
        ).implementation = function (x509CertificateArr, str, str2) {
            //console.log('  --> Bypassing Appmattus (CertificateTransparencyTrustManager)');
            return Java.use('java.util.ArrayList').$new();
        };
        //console.log('[+] Appmattus (CertificateTransparencyTrustManager)');
    } catch (err) {
        //console.log('[ ] Appmattus (CertificateTransparencyTrustManager)');
    }

    //console.log("Unpinning setup completed");
    //console.log("---");

}

function bypassLibProvider() {
    let LibContentProvider1 = Java.use("com.vnpay.sdktrainver3.LibContentProvider");
    LibContentProvider1["attachInfo"].implementation = function (context, providerInfo) {
        console.log(`LibContentProvider.attachInfo1 is called: context=${context}, providerInfo=${providerInfo}`);
        // this["attachInfo"](context, providerInfo);
    };

    let LibContentProvider = Java.use("com.vnpay.ekyc.LibContentProvider");
    LibContentProvider["attachInfo"].implementation = function (context, providerInfo) {
        console.log(`LibContentProvider.attachInfo is called: context=${context}, providerInfo=${providerInfo}`);
        // this["attachInfo"](context, providerInfo);
    };
    //spay
    let MainVer2Activity = Java.use("com.sacombank.ewallet.ui.activity.MainVer2Activity");
    MainVer2Activity["initEventAndData"].implementation = function () {
        console.log(`MainVer2Activity.initEventAndData is called`);
        this["initEventAndData"]();
    };
    let Utils = Java.use("com.sacombank.ewallet.utils.Utils");
    Utils["isDeviceRooted"].implementation = function () {
        console.log(`Utils.isDeviceRooted is called`);
        let result = false;
        console.log(`Utils.isDeviceRooted result=${result}`);
        return result;
    };
}



Java.perform(function () {
    bypassLibProvider();
    bypass_cert_pining_Long();
    // test();
    // check();

});





/**
 * ════════════════════════════════════════════════════════════════
 *  Sacombank Pay — SSL Pinning + Security Bypass v3.3
 *  Target : UAT — fiduat.iftdev.sacombank.com.vn
 *  Tested : Pixel 7 Pro (Android 14), Xiaomi MI 8 Lite (Android 10)
 * ════════════════════════════════════════════════════════════════
 *
 *  LAYER 1 — Java SSL pinning (OkHttp / TrustKit / custom)
 *  LAYER 2 — libsafehttp.so native TLS (ssl_verify_internal)
 *  LAYER 3 — libsecx.so integrity checks (NativeGUI / APKKiller)
 *  LAYER 4 — com.vnpay.domino CertValidationCallback (NFC flow)
 *
 * ────────────────────────────────────────────────────────────────
 *  CRASH / BUG HISTORY
 * ────────────────────────────────────────────────────────────────
 *
 *  [v1] ssl_verify_internal hook → SIGSEGV
 *       ctx->current_cert == NULL after early return → crash
 *       Fix: zero ctx->error + ctx->verify_result before return
 *
 *  [v2] fdsan SIGABRT on Pixel 7 Pro (Android 14)
 *       android_fdsan_exchange_owner_tag hook: wrong ARM64 signature
 *       Fix v3: Java hook NativeGUI.verify() → skip libsecx native
 *
 *  [v3] fdsan SIGABRT at handleBindApplication (script broke)
 *       hook android_fdsan_exchange_owner_tag → bad signature
 *       → JVM fd tagged "unowned" → abort at startup
 *
 *  [v3.1] close() inside NativeCallback → infinite recursion
 *         bionic close() == android_fdsan_close_with_tag
 *
 *  [v3.2] raw ARM64 SYS_close(57) → access violations
 *         Hook too broad → closed JVM/Frida fds → crash
 *
 *  [v3.3] FINAL: android_fdsan_set_error_level(WARN_ONCE)
 *         AOSP public API, no hooks needed, safe for entire process
 *
 *  [NFC -04! intermittent]
 *       HTTPSafe$1 (CertValidationCallback impl) hooked via
 *       Java.use() – class NOT loaded yet → safe() swallows error
 *       → hook never installed → race condition
 *       Fix: hook NativeGUI.impleInit() and replace callback arg
 *       with Java.registerClass() impl → deterministic, no race
 *
 * ────────────────────────────────────────────────────────────────
 *  libsafehttp.so OFFSETS (confirmed in IDA Pro):
 *    ssl_verify_internal       0x1E7C7C
 *    X509_verify_cert          0x15E804
 *    X509_STORE_CTX_get_error  0x15F548  → *(ctx + 176)
 *    error_mapper (sub_33D6C)  0x33D6C   → code 10 = "SSL server verification failed"
 * ════════════════════════════════════════════════════════════════
 */

"use strict";

// ─────────────────────────────────────────────────────────────
//  CONFIG
// ─────────────────────────────────────────────────────────────
const LIBSAFEHTTP = "libsafehttp.so";

const OFF = {
    ssl_verify_internal:      0x1E7C7C,
    X509_verify_cert:         0x15E804,
    X509_STORE_CTX_get_error: 0x15F548,
    error_mapper:             0x33D6C,
};

// ─────────────────────────────────────────────────────────────
//  UTILITIES
// ─────────────────────────────────────────────────────────────
function log(tag, msg) {
    console.log(`[BYPASS][${tag}] ${msg}`);
}

function safe(fn, tag) {
    try { fn(); }
    catch(e) { log("WARN", `${tag}: ${e}`); }
}

function hookWhenLoaded(libName, callback) {
    const mod = Process.findModuleByName(libName);
    if (mod) {
        callback(mod);
    } else {
        const id = setInterval(() => {
            const m = Process.findModuleByName(libName);
            if (m) { clearInterval(id); callback(m); }
        }, 200);
    }
}

// ─────────────────────────────────────────────────────────────
//  NATIVE — libsafehttp.so TLS hooks
//
//  ssl_verify_internal (0x1E7C7C):
//    Called by OpenSSL verify callback. Returns 1=OK, 0=FAIL.
//    When proxy cert fails, preverify_ok=0 → must force 1.
//    BUT: if we just return 1 early, caller reads ctx->current_cert
//    which may be NULL → SIGSEGV.
//    Fix: zero ctx->error (offset +176) and ctx->verify_result
//    before returning 1 so caller sees clean X509_V_OK state.
//
//  X509_verify_cert (0x15E804):
//    Chain verification. If returns 0 and ctx->error != 0,
//    caller triggers error mapper → -04! error string.
//    Fix: clear ctx->error on exit, return 1.
//
//  X509_STORE_CTX_get_error (0x15F548):
//    Reads *(ctx+176). Hook to always return 0 (X509_V_OK).
// ─────────────────────────────────────────────────────────────
function hookNativeSSL(mod) {
    const base = mod.base;

    // [1] ssl_verify_internal — early return forcing preverify_ok = 1
    safe(() => {
        const fn = base.add(OFF.ssl_verify_internal);
        Interceptor.attach(fn, {
            onEnter(args) {
                this.preverify = args[0].toInt32();
                this.ctx       = args[1];
            },
            onLeave(retval) {
                if (retval.toInt32() !== 1) {
                    log("NAT", `ssl_verify_internal: preverify=${this.preverify} → forcing 1`);
                    try {
                        if (!this.ctx.isNull()) {
                            this.ctx.add(176).writeU32(0); // ctx->error = X509_V_OK
                            this.ctx.add(180).writeU32(0); // ctx->verify_result = OK
                        }
                    } catch(_) {}
                    retval.replace(1);
                }
            }
        });
        log("OK", `ssl_verify_internal hooked @ ${fn}`);
    }, "ssl_verify_internal");

    // [2] X509_verify_cert — clear error on fail, force 1
    safe(() => {
        const fn = base.add(OFF.X509_verify_cert);
        Interceptor.attach(fn, {
            onEnter(args) { this.ctx = args[0]; },
            onLeave(retval) {
                if (retval.toInt32() !== 1) {
                    log("NAT", `X509_verify_cert: ${retval.toInt32()} → 1`);
                    try {
                        if (!this.ctx.isNull()) {
                            this.ctx.add(176).writeU32(0);
                            this.ctx.add(180).writeU32(0);
                        }
                    } catch(_) {}
                    retval.replace(1);
                }
            }
        });
        log("OK", `X509_verify_cert hooked @ ${fn}`);
    }, "X509_verify_cert");

    // [3] X509_STORE_CTX_get_error — always return X509_V_OK (0)
    safe(() => {
        const fn = base.add(OFF.X509_STORE_CTX_get_error);
        Interceptor.attach(fn, {
            onLeave(retval) {
                if (retval.toInt32() !== 0) {
                    retval.replace(0);
                }
            }
        });
        log("OK", `X509_STORE_CTX_get_error hooked @ ${fn}`);
    }, "X509_STORE_CTX_get_error");

    // [4] Error mapper monitor (logging only)
    safe(() => {
        const fn = base.add(OFF.error_mapper);
        Interceptor.attach(fn, {
            onEnter(args) {
                const code = args[0].toInt32();
                if (code === 10 || code === 11) {
                    log("ERR_MAPPER", `⚠️  error code=${code} triggered — should be suppressed by hooks above`);
                }
            }
        });
        log("OK", `error_mapper monitored @ ${fn}`);
    }, "error_mapper");

    log("NATIVE", "libsafehttp.so hooks installed ✓");
}

// ─────────────────────────────────────────────────────────────
//  NATIVE — fdsan suppression (Android 10+)
//
//  android_fdsan_set_error_level(WARN_ONCE):
//    Downgrades fdsan from FATAL (abort) to WARN_ONCE (log only).
//    AOSP public API — no hook on close/fclose needed.
//    Safe for JVM, Frida runtime, entire process.
//
//  ANDROID_FDSAN_ERROR_LEVEL values:
//    0 = WARN_ONCE   ← target
//    1 = WARN_ALWAYS
//    2 = FATAL       ← Android 14 default
// ─────────────────────────────────────────────────────────────
function hookFdsan() {
    safe(() => {
        const fn = Module.findExportByName("libc.so", "android_fdsan_set_error_level");
        if (!fn) {
            log("FDSAN", "android_fdsan_set_error_level not found (pre-Android 10), skip");
            return;
        }
        const setLevel = new NativeFunction(fn, 'int', ['int']);
        const prev = setLevel(0); // 0 = ANDROID_FDSAN_ERROR_LEVEL_WARN_ONCE
        log("OK",   `android_fdsan_set_error_level(WARN_ONCE) — prev level=${prev}`);
        log("FDSAN", "fdsan: FATAL → WARN_ONCE ✓");
    }, "fdsan_set_level");
}

// ─────────────────────────────────────────────────────────────
//  JAVA LAYER
// ─────────────────────────────────────────────────────────────
Java.perform(function () {
    log("INIT", "═══════════════════════════════════════════════");
    log("INIT", " Sacombank Pay SSL Bypass v3.3 — Starting");
    log("INIT", "═══════════════════════════════════════════════");

    // ════════════════════════════════════════════════════════════
    //  [A] com.vnpay.domino — HTTPSafe / NFC flow
    // ════════════════════════════════════════════════════════════

    safe(() => {
        // ─────────────────────────────────────────────────────────
        //  FIX 1: IllegalAccessError — interface package-private
        //    CertValidationCallback không có modifier public:
        //      ".class interface abstract Lcom/vnpay/domino/..."
        //    → Frida DEX ngoài không thể implement nó
        //    → Phải dùng app's own ClassLoader (Java.ClassFactory.get)
        //
        //  FIX 2: eccEncrypt varargs signature
        //    smali: ".method public static varargs eccEncrypt([Ljava/lang/String;)"
        //    → Phải gọi: eccEncrypt(Java.array('java.lang.String', ['VerifyOK']))
        //    → KHÔNG phải: eccEncrypt("VerifyOK")
        // ─────────────────────────────────────────────────────────

        // Bước 1: Tìm ClassLoader của app sở hữu com.vnpay.domino package
        let appLoader = null;
        Java.enumerateClassLoadersSync().forEach(loader => {
            if (appLoader) return;
            try {
                loader.loadClass("com.vnpay.domino.CertValidationCallback");
                appLoader = loader;
                log("DOMINO", `Found app ClassLoader: ${loader}`);
            } catch(_) {}
        });

        if (!appLoader) {
            log("DOMINO", "WARNING: Cannot find classloader for com.vnpay.domino — using default");
            appLoader = Java.classFactory.loader;
        }

        // Bước 2: Tạo ClassFactory với app's classloader
        const factory = Java.ClassFactory.get(appLoader);

        // Bước 3: Pre-compute eccEncrypt("VerifyOK") với signature đúng
        //   varargs → Java.array('java.lang.String', ['VerifyOK'])
        let cachedVerifyOK = null;
        try {
            const ServiceENC = factory.use("com.vnpay.domino.ServiceENC");
            const verifyOKArr = Java.array('java.lang.String', ['VerifyOK']);
            cachedVerifyOK = ServiceENC.eccEncrypt(verifyOKArr);
            log("DOMINO", `eccEncrypt("VerifyOK") pre-computed OK (len=${cachedVerifyOK.length})`);
        } catch(e) {
            log("DOMINO", `eccEncrypt pre-compute failed: ${e}`);
        }

        const CertValidationCB = factory.use("com.vnpay.domino.CertValidationCallback");
        const BypassCertCallback = factory.registerClass({
            name: "com.bypass.AlwaysValidCertCallback",
            implements: [CertValidationCB],
            methods: {
                // Tên JVM thực: "k" (JADX hiển thị là "mo8503k")
                // Smali: .method public abstract k([B)Ljava/lang/String;
                "k": {
                    returnType: "java.lang.String",
                    argumentTypes: ["[B"],
                    implementation: function(certBytes) {
                        log("DOMINO", "CertValidationCallback.k() → forced VerifyOK");
                        // Dùng cached value nếu có
                        if (cachedVerifyOK !== null) {
                            return cachedVerifyOK;
                        }
                        // Fallback: tính tại thời điểm callback
                        try {
                            const SE = factory.use("com.vnpay.domino.ServiceENC");
                            const arr = Java.array('java.lang.String', ['VerifyOK']);
                            cachedVerifyOK = SE.eccEncrypt(arr);
                            return cachedVerifyOK;
                        } catch(e) {
                            log("DOMINO", `eccEncrypt in-callback failed: ${e}`);
                            return "VerifyOK"; // plaintext fallback
                        }
                    }
                }
            }
        });

        log("OK", "BypassCertCallback registered via app ClassLoader");

        // Bước 5: Hook impleInit → inject bypass callback
        const NG = factory.use("com.vnpay.domino.NativeGUI");
        NG.impleInit.implementation = function(encData, sig, origCb, ctx, certs) {
            log("DOMINO", "impleInit() intercepted → injecting BypassCertCallback");
            return this.impleInit(encData, sig, BypassCertCallback.$new(), ctx, certs);
        };
        log("OK", "NativeGUI.impleInit hooked ✓");

        // Bước 6 (defense): Hook HTTPSafe$1 trực tiếp nếu đã load
        try {
            const cls = factory.use("com.vnpay.domino.HTTPSafe$1");
            cls["k"].implementation = function(certBytes) {
                log("DOMINO", "HTTPSafe$1.k() → VerifyOK");
                return cachedVerifyOK !== null ? cachedVerifyOK : "VerifyOK";
            };
            log("OK", "HTTPSafe$1.k() also hooked");
        } catch(_) {
            log("DOMINO", "HTTPSafe$1 not yet loaded (impleInit hook covers it)");
        }

    }, "domino_cert_callback");

    // Monitor các JNI calls cho debugging
    safe(() => {
        const NG = Java.use("com.vnpay.domino.NativeGUI");
        ["implePostMultipartNative", "implePostNative", "impleGetNative", "postUrlencodedNative"].forEach(m => {
            try {
                NG[m].implementation = function(...args) {
                    log("JNI", `${m}() called`);
                    const r = this[m](...args);
                    const s = r ? String(r).substring(0, 150) : "null";
                    if (s.includes("-04!")) {
                        log("JNI", `⚠️  ${m} → FAILED: ${s}`);
                    } else {
                        log("JNI", `${m} → OK (${s.length} chars)`);
                    }
                    return r;
                };
            } catch(_) {}
        });
        log("OK", "domino.NativeGUI methods monitored");
    }, "domino_monitor");

    // ════════════════════════════════════════════════════════════
    //  [B] com.vnpay.sec — libsecx.so integrity checks
    //
    //  APKKiller.verifyJs() → NativeGUI.verify() → libsecx.so
    //  libsecx.so: APK integrity check → crash vì env khác
    //  Fix: Intercept tại Java layer → native KHÔNG chạy
    // ════════════════════════════════════════════════════════════

    safe(() => {
        const SecNG = Java.use("com.vnpay.sec.NativeGUI");
        SecNG.verify.implementation = function(versionStr) {
            log("SECX", `NativeGUI.verify("${versionStr}") → bypass`);
            return JSON.stringify({ valid: "1", pkg: "com.sacombankpay", reason: "ok", t: Date.now() });
        };
        log("OK", "com.vnpay.sec.NativeGUI.verify hooked");
    }, "sec_verify");

    safe(() => {
        const SecNG = Java.use("com.vnpay.sec.NativeGUI");
        SecNG.start.implementation = function(ctx) {
            log("SECX", "NativeGUI.start() → bypass");
            return JSON.stringify({ valid: "1", pkg: "com.sacombankpay", reason: "ok", sign: "bypass", t: Date.now() });
        };
        log("OK", "com.vnpay.sec.NativeGUI.start hooked");
    }, "sec_start");

    safe(() => {
        const SecNG = Java.use("com.vnpay.sec.NativeGUI");
        SecNG.safe.implementation = function(str) {
            log("SECX", `NativeGUI.safe("${str}") → no-op`);
        };
        log("OK", "com.vnpay.sec.NativeGUI.safe hooked");
    }, "sec_safe");

    safe(() => {
        const SecNG = Java.use("com.vnpay.sec.NativeGUI");
        SecNG.savie.implementation = function(ctx, str) {
            log("SECX", `NativeGUI.savie("${str}") → no-op`);
        };
        log("OK", "com.vnpay.sec.NativeGUI.savie hooked");
    }, "sec_savie");

    safe(() => {
        const APK = Java.use("com.vnpay.sec.APKKiller");
        const JsonParser = Java.use("com.google.gson.JsonParser");
        APK.verifyJs.implementation = function() {
            log("SECX", "APKKiller.verifyJs() → bypass");
            try {
                return JsonParser.parseString('{"valid":"1","pkg":"com.sacombankpay","reason":"ok"}')
                    .getAsJsonObject();
            } catch(e) {
                log("SECX", `verifyJs gson error: ${e}`);
                return null;
            }
        };
        log("OK", "APKKiller.verifyJs hooked");
    }, "APKKiller_verifyJs");

    safe(() => {
        Java.use("com.vnpay.sec.APKKiller").verifyAndroid.implementation = function(ctx) {
            log("SECX", "APKKiller.verifyAndroid() → true");
            return true;
        };
        log("OK", "APKKiller.verifyAndroid hooked");
    }, "APKKiller_verifyAndroid");

    safe(() => {
        Java.use("com.vnpay.sec.APKKiller").processLib.implementation = function(ctx) {
            log("SECX", "APKKiller.processLib() → true");
            return true;
        };
        log("OK", "APKKiller.processLib hooked");
    }, "APKKiller_processLib");

    // ════════════════════════════════════════════════════════════
    //  [C] TrustKit — com.datatheorem.android.trustkit
    // ════════════════════════════════════════════════════════════

    safe(() => {
        Java.use("com.datatheorem.android.trustkit.pinning.PinningTrustManager")
            ["checkServerTrusted"]
            .overload("[Ljava.security.cert.X509Certificate;", "java.lang.String")
            .implementation = function() { log("TK", "PinningTrustManager bypassed"); };
        log("OK", "PinningTrustManager hooked");
    }, "PinningTrustManager");

    safe(() => {
        Java.use("com.datatheorem.android.trustkit.pinning.OkHttpRootTrustManager")
            ["checkServerTrusted"]
            .overload("[Ljava.security.cert.X509Certificate;", "java.lang.String")
            .implementation = function() { log("TK", "OkHttpRootTrustManager bypassed"); };
        log("OK", "OkHttpRootTrustManager hooked");
    }, "OkHttpRootTrustManager");

    // ════════════════════════════════════════════════════════════
    //  [D] OkHttp CertificatePinner
    // ════════════════════════════════════════════════════════════

    safe(() => {
        const CP = Java.use("okhttp3.CertificatePinner");
        CP["check"].overload("java.lang.String", "java.util.List")
            .implementation = function(host) {
                log("PINNER", `check("${host}") bypassed`);
            };
        try {
            CP["check$okhttp"].overload("java.lang.String", "java.util.List")
                .implementation = function(host) {
                    log("PINNER", `check$okhttp("${host}") bypassed`);
                };
        } catch(_) {}
        log("OK", "CertificatePinner hooked");
    }, "CertificatePinner");

    // ════════════════════════════════════════════════════════════
    //  [E] Sacombank custom interceptors
    // ════════════════════════════════════════════════════════════

    safe(() => {
        Java.use("com.spay.data.CertificatePinningInterceptor")["intercept"]
            .implementation = function(chain) {
                log("SPAY", "CertificatePinningInterceptor bypassed");
                return chain.proceed(chain.request());
            };
        log("OK", "CertificatePinningInterceptor hooked");
    }, "CertificatePinningInterceptor");

    safe(() => {
        const HCM = Java.use("com.spay.data.HttpClientManager");
        ["pinTrustedCertificatePublicKey", "pinMultipleTrustedCertificatePublicKey"].forEach(m => {
            try { HCM[m].implementation = function() { log("SPAY", `${m} bypassed`); }; } catch(_) {}
        });
        log("OK", "HttpClientManager hooked");
    }, "HttpClientManager");

    // ════════════════════════════════════════════════════════════
    //  [F] VNPAY SDK TrustManager delegates
    // ════════════════════════════════════════════════════════════

    [
        "com.vnpay.sdkcorekit.networks.BaseSDKTrustManagerDelegate",
        "com.vnpay.sdkfilmv3.networks.FlmTrustManagerDelegate",
        "com.vnpay.sdkvetauv2.networks.VtTrustManagerDelegate",
        "com.vnpay.vnpsdkiframe.networks.IFTrustManagerDelegate",
    ].forEach(cls => {
        safe(() => {
            Java.use(cls)["checkServerTrusted"]
                .overload("[Ljava.security.cert.X509Certificate;", "java.lang.String")
                .implementation = function() { log("TM", `${cls} bypassed`); };
            log("OK", `${cls} hooked`);
        }, cls);
    });

    // ════════════════════════════════════════════════════════════
    //  [G] OkHttp HostnameVerifier
    // ════════════════════════════════════════════════════════════

    safe(() => {
        const HVI = Java.use("javax.net.ssl.HostnameVerifier");
        Java.use("okhttp3.OkHttpClient$Builder")["hostnameVerifier"]
            .implementation = function(hv) {
                log("HOSTNAME", "Injecting always-true HostnameVerifier");
                const alwaysTrue = Java.registerClass({
                    name: "com.bypass.TrueHV_" + Date.now(),
                    implements: [HVI],
                    methods: {
                        verify: {
                            returnType: "boolean",
                            argumentTypes: ["java.lang.String", "javax.net.ssl.SSLSession"],
                            implementation: function(h, s) { return true; }
                        }
                    }
                });
                return this.hostnameVerifier(alwaysTrue.$new());
            };
        log("OK", "OkHttp HostnameVerifier hooked");
    }, "HostnameVerifier");

    // ════════════════════════════════════════════════════════════
    //  [H] Native hooks (deferred — wait for library load)
    // ════════════════════════════════════════════════════════════

    hookWhenLoaded(LIBSAFEHTTP, (mod) => {
        log("NATIVE", `libsafehttp.so loaded @ ${mod.base}`);
        hookNativeSSL(mod);
    });

    // fdsan: install immediately (does not need Java layer)
    hookFdsan();

    log("INIT", "All Java hooks installed ✓");
    log("INIT", "═══════════════════════════════════════════════");
});
