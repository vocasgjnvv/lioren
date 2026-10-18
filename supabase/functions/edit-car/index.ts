
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

async function hmac(
  key: Uint8Array,
  message: string,
): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  return await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    new TextEncoder().encode(message),
  );
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function verifyTelegram(
  initData: string,
  botToken: string,
): Promise<Record<string, unknown> | null> {
  try {
    const params = new URLSearchParams(initData);
    const receivedHash = params.get("hash");

    if (!receivedHash) return null;

    params.delete("hash");

    const checkString = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const secretKey = new Uint8Array(
      await hmac(
        new TextEncoder().encode("WebAppData"),
        botToken,
      ),
    );

    const calculatedHash = toHex(
      await hmac(secretKey, checkString),
    );

    if (calculatedHash !== receivedHash) return null;

    const authDate = Number(params.get("auth_date"));
    const now = Date.now() / 1000;

    if (
      !authDate ||
      now - authDate > 86400 ||
      authDate > now + 60
    ) {
      return null;
    }

    const userString = params.get("user");
    if (!userString) return null;

    return JSON.parse(userString);
  } catch {
    return null;
  }
}

Deno.serve(async (req) => {
  const json = (status: number, body: object) =>
    new Response(JSON.stringify(body), {
      status,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json",
      },
    });

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return json(405, { error: "Method not allowed" });
  }

  try {
    const {
      TELEGRAM_BOT_TOKEN,
      PROJECT_URL,
      SERVICE_ROLE_KEY,
    } = Deno.env.toObject();

    if (!TELEGRAM_BOT_TOKEN || !PROJECT_URL || !SERVICE_ROLE_KEY) {
      return json(500, {
        error: "Server secrets are not configured",
      });
    }

    let body: Record<string, unknown>;

    try {
      const parsed = await req.json();

      if (
        !parsed ||
        typeof parsed !== "object" ||
        Array.isArray(parsed)
      ) {
        return json(400, { error: "Invalid request body" });
      }

      body = parsed as Record<string, unknown>;
    } catch {
      return json(400, { error: "Invalid JSON body" });
    }

    if (typeof body.initData !== "string") {
      return json(401, {
        error: "Missing Telegram authorization",
      });
    }

    const user = await verifyTelegram(
      body.initData,
      TELEGRAM_BOT_TOKEN,
    );

    if (!user || !user.id) {
      return json(401, {
        error: "Telegram authorization failed",
      });
    }

    const carId = body.id;

    if (
      carId === undefined ||
      carId === null ||
      String(carId).trim() === ""
    ) {
      return json(400, { error: "Missing car ID" });
    }

    const allowedFields = [
      "name",
      "year",
      "price",
      "city",
      "description",
      "photo",
    ];

    const updates: Record<string, unknown> = {};

    for (const field of allowedFields) {
      if (Object.prototype.hasOwnProperty.call(body, field)) {
        updates[field] = body[field];
      }
    }

    if (Object.keys(updates).length === 0) {
      return json(400, { error: "No fields to update" });
    }

    const db = createClient(PROJECT_URL, SERVICE_ROLE_KEY);

    const { data: existing, error: findError } = await db
      .from("cars")
      .select("id, seller_telegram_id")
      .eq("id", carId)
      .maybeSingle();

    if (findError) {
      console.error("edit-car: lookup failed", findError);

      return json(500, {
        error: findError.message,
        code: findError.code,
        details: findError.details,
        hint: findError.hint,
      });
    }

    if (!existing) {
      return json(404, {
        error: "Объявление не найдено",
      });
    }

    if (
      String(existing.seller_telegram_id) !== String(user.id)
    ) {
      return json(403, {
        error: "Нет прав на изменение этого объявления",
      });
    }

    const { data, error: updateError } = await db
      .from("cars")
      .update(updates)
      .eq("id", carId)
      .select()
      .maybeSingle();

    if (updateError) {
      console.error("edit-car: update failed", updateError);

      return json(500, {
        error: updateError.message,
        code: updateError.code,
        details: updateError.details,
        hint: updateError.hint,
      });
    }

    if (!data) {
      return json(404, {
        error: "Обновление не выполнено: запись не найдена",
      });
    }

    return json(200, { data });
  } catch (error) {
    console.error("edit-car: unexpected error", error);

    return json(500, {
      error: error instanceof Error
        ? error.message
        : String(error),
    });
  }
});
