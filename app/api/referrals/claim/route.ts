import { NextRequest, NextResponse } from "next/server";
import { requireAuthenticatedUser } from "@/lib/auth/session";
import { enforceRouteRateLimit } from "@/lib/rate-limit";
import { sql } from "drizzle-orm";
import { getDb } from "@/lib/db/client";
import { normalizeReferralCode } from "@/lib/referrals/codes";
import { isRedirectError } from "next/dist/client/components/redirect-error";
import { isBoundedString } from "@/lib/http/request-validation";

/**
 * POST /api/referrals/claim
 *
 * Attributes the signed-in user to the referrer behind `code` (Issue #266).
 * Called once, right after a user signs up through an invite link.
 *
 * Attribution is deliberately server-side and idempotent:
 *   • record_referral() runs in SQL with the caller id taken from the session,
 *     so the referee cannot forge a row
 *   • the unique constraint on referee_id makes a double submit a no-op
 *   • self-referral is rejected in SQL as well as here
 *
 * Body: { code: string }
 */
export async function POST(request: NextRequest) {
  try {
    const rateLimitResponse = await enforceRouteRateLimit(request);
    if (rateLimitResponse) {
      return rateLimitResponse;
    }

    const { user } = await requireAuthenticatedUser();
    const db = getDb();
    if (!db) {
      return NextResponse.json({ error: "Database unavailable" }, { status: 503 });
    }

    const body = await request.json().catch(() => ({}));
    const rawCode = (body as { code?: unknown }).code;
    if (!isBoundedString(rawCode, 64)) {
      return NextResponse.json(
        { error: "A valid referral code is required" },
        { status: 400 },
      );
    }
    const code = normalizeReferralCode(rawCode);

    if (!code) {
      return NextResponse.json(
        { error: "A valid referral code is required" },
        { status: 400 },
      );
    }

    let row: { referral_id?: string; status?: string } | undefined;
    try {
      const result = await db.execute(
        sql`select referral_id, referrer_id, status from public.record_referral(${user.id}::uuid, ${code}::text)`,
      );
      row = result.rows[0] as typeof row;
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      // Map the SQL guards onto meaningful status codes rather than a blanket
      // 500 — an unknown code is a client mistake, not a server fault.
      if (message.includes("Unknown referral code")) {
        return NextResponse.json(
          { error: "That referral code does not exist" },
          { status: 404 },
        );
      }
      if (message.includes("Cannot refer yourself")) {
        return NextResponse.json(
          { error: "You cannot use your own referral link" },
          { status: 409 },
        );
      }
      console.error("Referral claim failed:", message);
      return NextResponse.json(
        { error: "Could not record your referral" },
        { status: 500 },
      );
    }

    return NextResponse.json(
      {
        referralId: row?.referral_id ? String(row.referral_id) : null,
        status: String(row?.status ?? "pending"),
        message:
          "Referral recorded. Your friend earns their bonus once your first loan is funded.",
      },
      { status: 200 },
    );
  } catch (error) {
    if (isRedirectError(error)) {
      throw error;
    }
    console.error("Referral claim error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
