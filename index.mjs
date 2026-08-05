// file: index.mjs
import admin from "firebase-admin";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb";

const client = new DynamoDBClient({});
const ddb = DynamoDBDocumentClient.from(client);

const TABLE_NAME = "detections";

const headers = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Allow-Methods": "GET,OPTIONS",
};

// firebase-admin: la credencial se lee de Secrets Manager (heimdall/firebase)
// en lugar de variables de entorno. Cae a las env vars solo si el secreto no
// está disponible, para permitir un rollback seguro.
const secretsClient = new SecretsManagerClient({
  region: process.env.AWS_REGION || "us-east-1",
});
const FIREBASE_SECRET_ID = process.env.FIREBASE_SECRET_ID || "heimdall/firebase";

let firebaseReady = null;
function ensureFirebase() {
  if (!firebaseReady) {
    firebaseReady = (async () => {
      if (admin.apps.length) return;
      let sa = null;
      try {
        const res = await secretsClient.send(
          new GetSecretValueCommand({ SecretId: FIREBASE_SECRET_ID })
        );
        const secret = JSON.parse(res.SecretString);
        sa = secret.service_account || secret;
      } catch (e) {
        if (!process.env.FIREBASE_PRIVATE_KEY) throw e;
      }
      const credential = sa
        ? admin.credential.cert({
            projectId: sa.project_id,
            clientEmail: sa.client_email,
            privateKey: sa.private_key,
          })
        : admin.credential.cert({
            projectId: process.env.FIREBASE_PROJECT_ID,
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
            privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
          });
      admin.initializeApp({ credential });
    })();
  }
  return firebaseReady;
}

// CORS: refleja el origen solo si está permitido (dominio de la app + previews
// de Vercel + localhost). Configurable con ALLOWED_ORIGINS (lista separada por
// comas). Antes se enviaba "*" a cualquier origen.
const STATIC_ALLOWED = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const DEFAULT_ORIGIN =
  STATIC_ALLOWED[0] || "https://harms-detection-landing-ui-seven.vercel.app";
function allowOrigin(event) {
  const origin =
    event?.headers?.origin || event?.headers?.Origin || "";
  const ok =
    STATIC_ALLOWED.includes(origin) ||
    /^https:\/\/([a-z0-9-]+\.)*vercel\.app$/i.test(origin) ||
    /^http:\/\/localhost(:\d+)?$/i.test(origin);
  return ok ? origin : DEFAULT_ORIGIN;
}

function getBearerToken(event) {
  const authHeader =
    event?.headers?.Authorization || event?.headers?.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }

  return authHeader.slice("Bearer ".length).trim();
}

export const handler = async (event) => {
  headers["Access-Control-Allow-Origin"] = allowOrigin(event);
  if (
    event?.requestContext?.http?.method === "OPTIONS" ||
    event?.httpMethod === "OPTIONS"
  ) {
    return {
      statusCode: 200,
      headers,
      body: "",
    };
  }

  try {
    const token = getBearerToken(event);

    if (!token) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ message: "Unauthorized: missing token" }),
      };
    }

    await ensureFirebase();
    const decodedToken = await admin.auth().verifyIdToken(token);
    const ownerUid = decodedToken.uid;

    const qs = event?.queryStringParameters ?? {};
    const limit = qs.limit ? Number(qs.limit) : 50;

    // Consulta por el GSI de dueño: el aislamiento lo impone la clave de la
    // consulta (owner_uid), no un filtro en memoria. Antes se leían los
    // dispositivos de TODOS los usuarios y luego se filtraba, lo que además
    // rompía la paginación (Limit se aplicaba antes del filtro).
    const result = await ddb.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        IndexName: "owner-index",
        KeyConditionExpression: "#owner = :owner",
        FilterExpression: "#type = :type",
        ExpressionAttributeNames: {
          "#owner": "owner_uid",
          "#type": "type",
        },
        ExpressionAttributeValues: {
          ":owner": ownerUid,
          ":type": "device",
        },
        ScanIndexForward: false,
        Limit: limit,
      })
    );

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        items: result.Items ?? [],
        lastEvaluatedKey: result.LastEvaluatedKey ?? null,
      }),
    };
  } catch (err) {
    const isAuthError = err?.code?.startsWith?.("auth/") === true;

    return {
      statusCode: isAuthError ? 401 : 500,
      headers,
      body: JSON.stringify({
        message: isAuthError ? "Unauthorized" : "Error listing items",
        error: err?.message ?? "Unknown error",
      }),
    };
  }
};
