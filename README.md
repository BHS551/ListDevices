# ListDevices

The AWS Lambda that returns a user's registered cameras for
[SkyEye](https://www.skyeyeprotection.com/).

One endpoint, one query: given a Firebase ID token, return the cameras that
belong to that user.

## The problem it solves

The obvious implementation of "list my cameras" on a shared table is a `Scan`
plus a filter on `owner_uid`. It works on day one and is wrong in three ways
that only show up later:

1. **Isolation depends on code.** Every row in the table is read, and one
   mistake in the filter shows a customer somebody else's cameras.
2. **Cost scales with the whole table**, not with the user's data. Everyone
   pays to read everyone.
3. **Pagination is silently broken.** DynamoDB applies `Limit` *before* the
   filter, so `limit=50` returns the matches within the first 50 rows scanned —
   which can be none at all while more exist.

This version queries an `owner-index` GSI keyed on `owner_uid` instead, so
isolation is enforced by the key rather than by a filter, and `Limit` operates
inside the user's own data.

## How it works

```
GET /?limit=50     Authorization: Bearer <Firebase ID token>
   │
   ▼
verifyIdToken()  ──► ownerUid   (401 if missing or invalid)
   │
   ▼
Query `detections`
   IndexName            owner-index
   KeyCondition         owner_uid = <uid from the token>     ← isolation
   FilterExpression     type = "device"                      ← row kind
   ScanIndexForward     false                                ← newest first
   │
   ▼
200 { items, lastEvaluatedKey }
```

The `uid` comes from the verified token and is never read from a query string
or request body, so a caller cannot ask for another user's cameras.

`type = "device"` stays a filter rather than part of the key, because it only
separates cameras from detection events inside one user's already-small result
set — the expensive dimension is the owner, and that is the key.

## Key technical decisions

**Isolation is structural.** Because `owner_uid` is the partition key of the
GSI, there is no code path that returns another user's rows. Removing the
filter would return the user's events too — never someone else's cameras.

**Newest first, by default.** `ScanIndexForward: false` puts the most recently
added camera at the top, which is what the console wants without sorting
client-side.

**Pagination is honest.** `lastEvaluatedKey` is returned as-is so the caller can
continue where it left off. Since `Limit` now applies within the user's
partition, a full page means a full page.

**`raw` is returned verbatim.** Cameras are stored with their payload in a
`raw` JSON string, so the API surface does not have to change every time a
field is added to a camera.

**Only `auth/*` errors are 401.** Anything else, including AWS SDK credential
problems, is a 500.

## API

```http
GET /?limit=50
Authorization: Bearer <Firebase ID token>
```

```json
{
  "items": [
    { "type": "device", "id": "…", "owner_uid": "…", "created_at": "…", "raw": "{…}" }
  ],
  "lastEvaluatedKey": null
}
```

`limit` defaults to 50. `OPTIONS` returns 200 with the CORS headers.

Cameras are created by
[StoreDevice](https://github.com/BHS551/StoreDevice), which is also why
`raw.rtsp_path` here is masked — the real credential lives in Secrets Manager
and never reaches this response.

## Deploying

Node.js 18+ on AWS Lambda behind API Gateway, handler `index.mjs`.

```bash
npm install firebase-admin @aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb \
            @aws-sdk/client-secrets-manager
zip -r function.zip . && aws lambda update-function-code \
  --function-name listDevices --zip-file fileb://function.zip
```

Requires the `detections` table with an `owner-index` GSI on `owner_uid`. The
execution role needs `dynamodb:Query` on that index and
`secretsmanager:GetSecretValue` on the Firebase secret.

| Variable | Default | Meaning |
|---|---|---|
| `FIREBASE_SECRET_ID` | `heimdall/firebase` | Service account secret id |
| `ALLOWED_ORIGINS` | — | Comma-separated CORS allow-list |
