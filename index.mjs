// file: index.mjs
import admin from "firebase-admin";
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

if (
  !process.env.FIREBASE_PROJECT_ID ||
  !process.env.FIREBASE_CLIENT_EMAIL ||
  !process.env.FIREBASE_PRIVATE_KEY
) {
  throw new Error("Missing Firebase environment variables");
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    }),
  });
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
