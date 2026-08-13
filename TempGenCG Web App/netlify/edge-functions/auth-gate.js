// Netlify Edge Function: simple server-side password gate
// The password is read from an Environment Variable (Netlify.env),
// so it never appears in any file that gets shipped to the browser.

const COOKIE_NAME = "jp_session";
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7 days

function loginPage(error) {
  return `<!DOCTYPE html>
<html lang="bn">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>JobPost Studio | Login</title>
<style>
  *{box-sizing:border-box;}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:#1a1a2e;font-family:'Segoe UI',Arial,sans-serif;}
  .card{background:#fff;padding:36px 32px;border-radius:14px;width:90%;max-width:360px;
    text-align:center;box-shadow:0 10px 40px rgba(0,0,0,0.3);}
  .title{font-size:18px;font-weight:700;color:#1a1a2e;margin-bottom:6px;}
  .sub{font-size:13px;color:#666;margin-bottom:18px;}
  input{width:100%;padding:10px 12px;border:1px solid #ccc;border-radius:8px;
    font-size:14px;margin-bottom:12px;box-sizing:border-box;}
  button{width:100%;padding:10px;border:none;border-radius:8px;background:#1a1a2e;
    color:#fff;font-size:14px;font-weight:500;cursor:pointer;}
  .err{color:#d9534f;font-size:12px;margin-top:10px;}
</style>
</head>
<body>
  <div class="card">
    <div class="title">TempGen | Capgemini</div>
    <div class="sub">To Visit This Site Enter The Password</div>
    <form method="POST">
      <input type="password" name="password" placeholder="Password" autofocus required>
      <button type="submit">Enter</button>
    </form>
    ${error ? `<div class="err">Wrong Password, Try Again</div>` : ""}
  </div>
</body>
</html>`;
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("cookie") || "";
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? match[1] : null;
}

export default async (request, context) => {
  const correctPassword = Netlify.env.get("SITE_PASSWORD");
  const sessionSecret = Netlify.env.get("SESSION_SECRET") || correctPassword;

  // Expected cookie value = a simple derived token (not the raw password)
  const expectedToken = await sha256(sessionSecret);

  const url = new URL(request.url);

  // Handle login form submission
  if (request.method === "POST") {
    const form = await request.formData();
    const submitted = form.get("password");

    if (submitted === correctPassword) {
      const headers = new Headers();
      headers.set("Location", url.pathname);
      headers.append(
        "Set-Cookie",
        `${COOKIE_NAME}=${expectedToken}; Path=/; Max-Age=${COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Lax`
      );
      return new Response(null, { status: 302, headers });
    }

    return new Response(loginPage(true), {
      status: 401,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  // Check existing session cookie
  const cookieValue = getCookie(request, COOKIE_NAME);
  if (cookieValue === expectedToken) {
    return context.next(); // let the real site through
  }

  // No valid session -> show login page
  return new Response(loginPage(false), {
    status: 401,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
};

async function sha256(text) {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export const config = { path: "/*" };
