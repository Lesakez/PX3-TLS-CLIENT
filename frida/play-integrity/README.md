# Play Integrity monitor (Frida)

A **read-only** Frida script that observes how a test application uses the Google
Play Integrity API. It confirms that the integrity check is actually invoked and
prints the request parameters and the resulting token (or error) — without
modifying arguments, spoofing verdicts, or otherwise changing the app's
behavior. Use it to *verify* your integration or to inspect an app you own or are
authorized to test.

## What it hooks

Both API generations are covered:

| API | Hooked call | What you see |
|-----|-------------|--------------|
| Classic | `IntegrityManager.requestIntegrityToken(request)` | nonce, cloud project number, call stack |
| Classic | `IntegrityTokenResponse.token()` | the returned integrity token |
| Standard | `StandardIntegrityManager.prepareIntegrityToken(...)` | warm-up call + cloud project number |
| Standard | `StandardIntegrityTokenProvider.request(...)` | request hash, call stack |
| Standard | `StandardIntegrityToken.token()` | the returned integrity token |

The result of each request is captured by attaching `OnSuccessListener` /
`OnFailureListener` to the returned Play Services `Task`, so you get the outcome
even when the app resolves it asynchronously. Failures are decoded against the
`IntegrityErrorCode` table (e.g. `-3 NETWORK_ERROR`, `-8 TOO_MANY_REQUESTS`).

## Requirements

- A rooted device/emulator with `frida-server` running, **or** a repackaged
  debuggable build of your test app bundled with `frida-gadget`.
- `frida` / `frida-tools` on the host (`pip install frida-tools`).
- A device you own or are authorized to test.

## Run

Spawn the app under instrumentation (recommended, so the warm-up call is caught):

```bash
frida -U -f your.test.package -l play-integrity-monitor.js --no-pause
```

Attach to an already-running app:

```bash
frida -U -n YourAppName -l play-integrity-monitor.js
```

## Example output

```
[2026-09-28T19:05:11.204Z][play-integrity][init] Play Integrity monitor loaded — read-only observation, no behavior changes.
[2026-09-28T19:05:11.210Z][play-integrity][init] hooked StandardIntegrityManager.prepareIntegrityToken
[2026-09-28T19:05:11.212Z][play-integrity][init] hooked StandardIntegrityTokenProvider.request
[2026-09-28T19:05:14.880Z][play-integrity][standard] >>> prepareIntegrityToken() CALLED (warm-up)
[2026-09-28T19:05:14.881Z][play-integrity][standard] cloudProjectNumber = 123456789012
[2026-09-28T19:05:16.001Z][play-integrity][standard] >>> StandardIntegrityTokenProvider.request() CALLED
[2026-09-28T19:05:16.002Z][play-integrity][standard] requestHash = a1b2c3…
[2026-09-28T19:05:16.740Z][play-integrity][standard] RESULT = SUCCESS, integrity token: len=1024 head=eyJ0eXAiOiJKV1Qi… tail=…AbCdEf
```

If the app fails the check you'll instead see a decoded error, e.g.:

```
[...][play-integrity][standard] RESULT = FAILURE: ...IntegrityServiceException... [errorCode=-3 (NETWORK_ERROR)]
```

## Notes

- If `Classic requestIntegrityToken not hooked yet` appears at startup, the class
  hasn't loaded — the classic API is often pulled in on demand. Start the flow in
  the app and the request will still be logged once the class is present. For
  early classes, spawn with `-f` rather than attaching.
- Tokens are truncated in the log (head/tail + length) to keep output readable;
  send the full token to your server to decode the verdict via the Play Integrity
  API — this script deliberately does not do that for you.
