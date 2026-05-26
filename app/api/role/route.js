import { createClient } from "@supabase/supabase-js";

export async function GET(request) {
  const SUPERADMIN_EMAILS = (process.env.SUPERADMIN_EMAILS || "")
    .split(",")
    .map(e => e.trim().toLowerCase());

  // Leer el token del header Authorization
  const authHeader = request.headers.get("authorization") || "";
  const token = authHeader.replace("Bearer ", "").trim();

  if (!token) return Response.json({ role: "member", debug: "no-token" });

  // Usar el cliente estándar con el token del usuario
  const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    { global: { headers: { Authorization: `Bearer ${token}` } } }
  );

  const { data: { user }, error } = await supabase.auth.getUser(token);

  if (!user) return Response.json({ role: "member", debug: "no-user", error: error?.message });

  const role = SUPERADMIN_EMAILS.includes(user.email.toLowerCase())
    ? "superadmin"
    : "member";

  return Response.json({ role, debug: { email: user.email, list: SUPERADMIN_EMAILS, match: SUPERADMIN_EMAILS.includes(user.email.toLowerCase()) } });
}