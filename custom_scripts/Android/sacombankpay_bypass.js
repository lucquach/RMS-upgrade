/**
 * sacombankpay_bypass.js
 * Bypass VNPAY anti-Frida protections in com.sacombankpay
 *
 * Detected protection points:
 *   1. DP:751  — LibContentProvider.attachInfo() (VNPAY SDK init-time check)
 *   2. NPE     — VnpAppEn.run() called from BaseActivity.onResume() every Activity resume
 *
 * Usage: Paste this into RMS → Load Frida Script BEFORE tapping Spawn.
 *        Script is loaded before device.resume() so hooks are active at startup.
 */

Java.perform(function () {

  /* ── 1. Bypass VnpAppEn.run() (NPE in onResume) ─────────────────────────
   *
   * com.vnp.vnpapp.VnpAppEn has both a Java run(SourceFile:123) and a
   * native run() that computes an obfuscated class name.
   * Under Frida the native call returns null → Class.forName(null) → NPE.
   * We override the Java run() to no-op so onResume() continues safely.
   */
  try {
    var VnpAppEn = Java.use('com.vnp.vnpapp.VnpAppEn');
    // Override every overload that might exist
    VnpAppEn.run.overloads.forEach(function (overload) {
      overload.implementation = function () {
        console.log('[BYPASS] VnpAppEn.run() suppressed (anti-Frida check #2)');
        // Return void / null — do NOT call original
      };
    });
    console.log('[+] VnpAppEn.run() hooked successfully');
  } catch (e) {
    console.log('[!] VnpAppEn hook failed: ' + e);

    /* Fallback: wrap BaseActivity.onResume in try/catch so NPE is swallowed */
    try {
      var BaseActivity = Java.use('com.vnpay.ekyc.core.BaseActivity');
      BaseActivity.onResume.implementation = function () {
        try {
          this.onResume();
        } catch (err) {
          console.log('[BYPASS] BaseActivity.onResume exception suppressed: ' + err);
        }
      };
      console.log('[+] BaseActivity.onResume wrapped (fallback)');
    } catch (e2) {
      console.log('[!] BaseActivity fallback also failed: ' + e2);
    }
  }

  /* ── 2. Bypass DP:751 — LibContentProvider early init check ─────────────
   *
   * com.vnpay.sdktrainver3.LibContentProvider.attachInfo() calls a native
   * method pmoqlcmJxF() which detects Frida → throws RuntimeException DP:751.
   * We hook the ContentProvider before it runs.
   */
  try {
    var LibCP = Java.use('com.vnpay.sdktrainver3.LibContentProvider');
    LibCP.attachInfo.overloads.forEach(function (overload) {
      overload.implementation = function () {
        console.log('[BYPASS] LibContentProvider.attachInfo() suppressed (DP:751)');
      };
    });
    console.log('[+] LibContentProvider.attachInfo() hooked (DP:751 bypass)');
  } catch (e) {
    console.log('[!] LibContentProvider hook failed: ' + e);
  }

  /* ── 3. Safety net: suppress Class.forName(null) NPEs globally ──────────
   *
   * If any other VNPAY module does the same pattern (native returns null →
   * Class.forName(null)), this guard catches it and returns null instead of
   * crashing. Callers that don't null-check will still fail, but this may
   * absorb unknown future check points.
   */
  try {
    var JavaClass = Java.use('java.lang.Class');
    var forNameStr = JavaClass.forName.overload('java.lang.String');
    forNameStr.implementation = function (name) {
      if (name === null || name === undefined) {
        console.log('[BYPASS] Class.forName(null) intercepted — returning null safely');
        return null;
      }
      try {
        return forNameStr.call(this, name);
      } catch (e) {
        console.log('[BYPASS] Class.forName("' + name + '") threw: ' + e + ' — returning null');
        return null;
      }
    };
    console.log('[+] Class.forName safety net installed');
  } catch (e) {
    console.log('[!] Class.forName hook failed: ' + e);
  }

  console.log('[*] sacombankpay_bypass.js loaded — all hooks active');
});
