function escapeHtml(input: string) {
  return input
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function page(title: string, body: string) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    :root { color-scheme: light; }
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; max-width: 760px; margin: 40px auto; padding: 0 16px; line-height: 1.5; }
    .card { border: 1px solid #ddd; border-radius: 16px; padding: 24px; }
    input, button { width: 100%; box-sizing: border-box; padding: 12px 14px; margin: 8px 0; border-radius: 10px; border: 1px solid #ccc; }
    button { cursor: pointer; border: 0; background: #111827; color: white; font-weight: 600; }
    .error { color: #b00020; }
    .muted { color: #666; font-size: 14px; }
    a { color: #2563eb; }
    code { background: #f3f4f6; padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>${body}</body>
</html>`;
}

export function loginPage(opts: { returnTo: string; error?: string }) {
  return page(
    "Login",
    `<div class="card">
      <h1>Sign in</h1>
      <p class="muted">Authenticate with my-auth to continue.</p>
      ${opts.error ? `<p class="error">${escapeHtml(opts.error)}</p>` : ""}
      <form method="post" action="/login">
        <input type="hidden" name="returnTo" value="${escapeHtml(opts.returnTo)}" />
        <input name="email" type="email" autocomplete="email" placeholder="Email" required />
        <input name="password" type="password" autocomplete="current-password" placeholder="Password" required />
        <button type="submit">Sign in</button>
      </form>
      <p class="muted">No account yet? <a href="/signup?returnTo=${encodeURIComponent(opts.returnTo)}">Create one</a></p>
    </div>`
  );
}

export function signupPage(opts: { returnTo: string; error?: string }) {
  return page(
    "Sign up",
    `<div class="card">
      <h1>Create account</h1>
      <p class="muted">Create your my-auth identity.</p>
      ${opts.error ? `<p class="error">${escapeHtml(opts.error)}</p>` : ""}
      <form method="post" action="/signup">
        <input type="hidden" name="returnTo" value="${escapeHtml(opts.returnTo)}" />
        <input name="name" type="text" autocomplete="name" placeholder="Name" required />
        <input name="email" type="email" autocomplete="email" placeholder="Email" required />
        <input name="password" type="password" autocomplete="new-password" placeholder="Password (min 8 chars)" required />
        <button type="submit">Create account</button>
      </form>
      <p class="muted">Already have an account? <a href="/login?returnTo=${encodeURIComponent(opts.returnTo)}">Sign in</a></p>
    </div>`
  );
}
