# ListDevices

Lambda de **SkyEye** que lista las cámaras del usuario autenticado.

> 📚 Contexto completo del proyecto: `docs/SKYEYE_PROJECT.md` en el repo
> `harmsDetectionLandingUi`.

## Qué hace

`GET` (con `Authorization: Bearer <ID token Firebase>`): consulta DynamoDB
(`detections`) por el GSI **`owner-index`** con `owner_uid` = uid del token y
`type = "device"`, ordenado del más reciente al más antiguo, con `?limit=`
opcional (default 50). Devuelve `{ items, lastEvaluatedKey }`.

El aislamiento por usuario lo impone la **clave de la consulta** (el GSI), no
un filtro en memoria — antes se leían los dispositivos de todos los usuarios y
se filtraba después, lo que además rompía la paginación.

## Detalles

- Credenciales de Firebase desde Secrets Manager (`heimdall/firebase`), con
  fallback a env vars para rollback.
- CORS restringido (dominio de la app + previews Vercel + localhost,
  configurable con `ALLOWED_ORIGINS`).
- Solo errores `auth/*` de firebase-admin devuelven 401.

## Variables de entorno

`FIREBASE_SECRET_ID` (default `heimdall/firebase`), `ALLOWED_ORIGINS`,
`AWS_REGION` (default `us-east-1`).

## Relacionados

- `StoreDevice` — alta de cámaras.
- `ListDetections` — mismo patrón, para los eventos de detección.
