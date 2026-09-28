/*
 * play-integrity-monitor.js
 *
 * Frida instrumentation script that OBSERVES how a test application uses the
 * Google Play Integrity API. It is a read-only monitor: it hooks the public
 * Play Integrity entry points, logs each request (nonce / request hash), and
 * logs the resulting token or error. It does NOT modify arguments, spoof a
 * verdict, or change the outcome in any way — it only reports what the app is
 * actually doing so you can verify the call is made and inspect the result.
 *
 * Covers both API generations:
 *   - Classic API   : IntegrityManager.requestIntegrityToken(...)  -> IntegrityTokenResponse.token()
 *   - Standard API  : StandardIntegrityManager
 *                        .prepareIntegrityToken(...)               (warm-up)
 *                        StandardIntegrityTokenProvider.request(...) -> StandardIntegrityToken.token()
 *
 * Usage:
 *   frida -U -f <your.test.package> -l play-integrity-monitor.js --no-pause
 *   # or attach to a running process:
 *   frida -U -n <AppName> -l play-integrity-monitor.js
 *
 * Requires: a rooted device/emulator (or a repackaged debuggable app with
 * frida-gadget) that you own or are authorized to test.
 */

'use strict';

/* ----------------------------- small helpers ----------------------------- */

function ts() {
  return new Date().toISOString();
}

function log(tag, msg) {
  console.log('[' + ts() + '][play-integrity][' + tag + '] ' + msg);
}

// Turn a Java byte[] into a short base64 + hex preview so nonces are readable
// without dumping huge blobs.
function bytesPreview(bytes) {
  if (bytes === null) return 'null';
  try {
    var Base64 = Java.use('android.util.Base64');
    var NO_WRAP = 2;
    var b64 = Base64.encodeToString(bytes, NO_WRAP);
    var len = bytes.length;
    var short = b64.length > 96 ? b64.substring(0, 96) + '…(' + b64.length + ' chars)' : b64;
    return 'len=' + len + ' b64=' + short;
  } catch (e) {
    return '<unprintable byte[]: ' + e + '>';
  }
}

// Print a token but keep the log readable: show head/tail and length only.
function tokenPreview(token) {
  if (token === null || token === undefined) return 'null';
  var s = '' + token;
  if (s.length <= 120) return 'len=' + s.length + ' value=' + s;
  return 'len=' + s.length + ' head=' + s.substring(0, 60) + '… tail=…' + s.substring(s.length - 20);
}

function printStack() {
  try {
    var Exception = Java.use('java.lang.Exception');
    var Log = Java.use('android.util.Log');
    log('stack', Log.getStackTraceString(Exception.$new()));
  } catch (e) {
    log('stack', '<unavailable: ' + e + '>');
  }
}

// Attach success/failure listeners to a Play Services Task without consuming it.
// Returns the (still untouched) task.
function observeTask(task, label) {
  if (task === null || task === undefined) {
    log(label, 'request returned a null Task');
    return task;
  }
  try {
    var OnSuccess = Java.use('com.google.android.gms.tasks.OnSuccessListener');
    var OnFailure = Java.use('com.google.android.gms.tasks.OnFailureListener');

    var successCb = Java.registerClass({
      name: 'com.frida.PIOnSuccess_' + label + '_' + Math.floor(Math.random() * 1e9),
      implements: [OnSuccess],
      methods: {
        onSuccess: function (result) {
          try {
            handleResponse(label, result);
          } catch (e) {
            log(label, 'onSuccess handler error: ' + e);
          }
        }
      }
    });

    var failureCb = Java.registerClass({
      name: 'com.frida.PIOnFailure_' + label + '_' + Math.floor(Math.random() * 1e9),
      implements: [OnFailure],
      methods: {
        onFailure: function (ex) {
          log(label, 'RESULT = FAILURE: ' + describeException(ex));
        }
      }
    });

    task.addOnSuccessListener(successCb.$new());
    task.addOnFailureListener(failureCb.$new());
  } catch (e) {
    log(label, 'could not attach Task listeners (' + e + '); falling back to return-value hooks');
  }
  return task;
}

// Decode an IntegrityErrorCode number if the exception carries one.
var ERROR_CODES = {
  '-1': 'API_NOT_AVAILABLE',
  '-2': 'PLAY_STORE_NOT_FOUND',
  '-3': 'NETWORK_ERROR',
  '-4': 'PLAY_STORE_ACCOUNT_NOT_FOUND',
  '-5': 'APP_NOT_INSTALLED',
  '-6': 'PLAY_SERVICES_NOT_FOUND',
  '-7': 'APP_UID_MISMATCH',
  '-8': 'TOO_MANY_REQUESTS',
  '-9': 'CANNOT_BIND_TO_SERVICE',
  '-10': 'NONCE_TOO_SHORT',
  '-11': 'NONCE_TOO_LONG',
  '-12': 'GOOGLE_SERVER_UNAVAILABLE',
  '-13': 'NONCE_IS_NOT_BASE64',
  '-14': 'PLAY_STORE_VERSION_OUTDATED',
  '-15': 'PLAY_SERVICES_VERSION_OUTDATED',
  '-16': 'CLOUD_PROJECT_NUMBER_IS_INVALID',
  '-17': 'CLIENT_TRANSIENT_ERROR',
  '-100': 'INTERNAL_ERROR',
  '0': 'NO_ERROR'
};

function describeException(ex) {
  if (ex === null || ex === undefined) return 'null';
  var out = '' + ex;
  try {
    var IntegrityException = Java.use('com.google.android.play.core.integrity.model.IntegrityErrorCode');
    // Many builds expose getErrorCode() on the exception subclass.
    if (typeof ex.getErrorCode === 'function') {
      var code = ex.getErrorCode();
      out += ' [errorCode=' + code + ' (' + (ERROR_CODES['' + code] || 'UNKNOWN') + ')]';
    }
  } catch (e) {
    /* not all builds expose these; ignore */
  }
  return out;
}

/* --------------------------- response handling --------------------------- */

function handleResponse(label, response) {
  if (response === null || response === undefined) {
    log(label, 'RESULT = SUCCESS but response object is null');
    return;
  }
  var token = null;
  try {
    if (typeof response.token === 'function') {
      token = response.token();
    }
  } catch (e) {
    log(label, 'could not read token(): ' + e);
  }
  log(label, 'RESULT = SUCCESS, integrity token: ' + tokenPreview(token));
}

/* ------------------------------- hooks ----------------------------------- */

function hookClassicApi() {
  var found = false;

  // IntegrityManager.requestIntegrityToken(IntegrityTokenRequest)
  try {
    var IntegrityManager = Java.use('com.google.android.play.core.integrity.IntegrityManager');
    IntegrityManager.requestIntegrityToken.overload(
      'com.google.android.play.core.integrity.IntegrityTokenRequest'
    ).implementation = function (request) {
      found = true;
      log('classic', '>>> requestIntegrityToken() CALLED');
      try {
        var nonce = request.nonce();
        log('classic', 'nonce = ' + (nonce === null ? 'null' : ('"' + nonce + '"')));
      } catch (e) { /* nonce() may be a String on this build */ }
      try {
        if (typeof request.cloudProjectNumber === 'function') {
          log('classic', 'cloudProjectNumber = ' + request.cloudProjectNumber());
        }
      } catch (e) { /* optional */ }
      printStack();

      var task = this.requestIntegrityToken(request);
      return observeTask(task, 'classic');
    };
    log('init', 'hooked IntegrityManager.requestIntegrityToken');
  } catch (e) {
    log('init', 'classic IntegrityManager not present: ' + e);
  }

  // Some builds also expose an IntegrityTokenRequest.Builder we can watch to see
  // exactly what nonce the app sets (the request object above may hide it).
  try {
    var Builder = Java.use('com.google.android.play.core.integrity.IntegrityTokenRequest$Builder');
    if (Builder.setNonce) {
      Builder.setNonce.overload('java.lang.String').implementation = function (nonce) {
        log('classic', 'Builder.setNonce("' + nonce + '")');
        return this.setNonce(nonce);
      };
      log('init', 'hooked IntegrityTokenRequest.Builder.setNonce');
    }
  } catch (e) { /* optional */ }

  // Direct token() read as a fallback if the app resolves the Task synchronously.
  try {
    var Response = Java.use('com.google.android.play.core.integrity.IntegrityTokenResponse');
    Response.token.implementation = function () {
      var t = this.token();
      log('classic', 'IntegrityTokenResponse.token() read: ' + tokenPreview(t));
      return t;
    };
    log('init', 'hooked IntegrityTokenResponse.token');
  } catch (e) { /* optional */ }

  return found;
}

function hookStandardApi() {
  // StandardIntegrityManager.prepareIntegrityToken(PrepareIntegrityTokenRequest) — warm-up
  try {
    var StdMgr = Java.use('com.google.android.play.core.integrity.StandardIntegrityManager');
    var m = StdMgr.prepareIntegrityToken;
    if (m) {
      m.overload(
        'com.google.android.play.core.integrity.StandardIntegrityManager$PrepareIntegrityTokenRequest'
      ).implementation = function (req) {
        log('standard', '>>> prepareIntegrityToken() CALLED (warm-up)');
        try {
          if (typeof req.cloudProjectNumber === 'function') {
            log('standard', 'cloudProjectNumber = ' + req.cloudProjectNumber());
          }
        } catch (e) { /* optional */ }
        printStack();
        var task = this.prepareIntegrityToken(req);
        // The prepare Task yields a StandardIntegrityTokenProvider, not a token.
        observeTask(task, 'standard-prepare');
        return task;
      };
      log('init', 'hooked StandardIntegrityManager.prepareIntegrityToken');
    }
  } catch (e) {
    log('init', 'standard StandardIntegrityManager not present: ' + e);
  }

  // StandardIntegrityTokenProvider.request(StandardIntegrityTokenRequest) -> token
  try {
    var Provider = Java.use(
      'com.google.android.play.core.integrity.StandardIntegrityManager$StandardIntegrityTokenProvider'
    );
    Provider.request.overload(
      'com.google.android.play.core.integrity.StandardIntegrityManager$StandardIntegrityTokenRequest'
    ).implementation = function (req) {
      log('standard', '>>> StandardIntegrityTokenProvider.request() CALLED');
      try {
        if (typeof req.requestHash === 'function') {
          log('standard', 'requestHash = ' + req.requestHash());
        }
      } catch (e) { /* optional */ }
      printStack();
      var task = this.request(req);
      return observeTask(task, 'standard');
    };
    log('init', 'hooked StandardIntegrityTokenProvider.request');
  } catch (e) {
    log('init', 'StandardIntegrityTokenProvider not present: ' + e);
  }

  // StandardIntegrityToken.token() fallback read.
  try {
    var StdToken = Java.use(
      'com.google.android.play.core.integrity.StandardIntegrityManager$StandardIntegrityToken'
    );
    StdToken.token.implementation = function () {
      var t = this.token();
      log('standard', 'StandardIntegrityToken.token() read: ' + tokenPreview(t));
      return t;
    };
    log('init', 'hooked StandardIntegrityToken.token');
  } catch (e) { /* optional */ }
}

/* ------------------------------- bootstrap ------------------------------- */

Java.perform(function () {
  log('init', 'Play Integrity monitor loaded — read-only observation, no behavior changes.');
  var classic = hookClassicApi();
  hookStandardApi();
  if (!classic) {
    log('init', 'Classic requestIntegrityToken not hooked yet (class may load later). ' +
      'If the app uses Play Core dynamic feature loading, re-run after the integrity flow starts.');
  }
  log('init', 'Waiting for the app to invoke Play Integrity…');
});
