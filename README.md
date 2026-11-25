# Travel Horizon

The admin panel includes a visual editor for homepage and destination text, photo URLs, and photo uploads. Editable copy is stored in PostgreSQL; uploaded photos are stored in `data/uploads/`. An advanced source editor is also available for the public files in `public/`.

## Project layout

- `public/` contains the visitor-facing page, styles, scripts, and translations.
- `admin/` contains the admin page, styles, and editor scripts.
- `data/content.json` is imported once to seed an empty PostgreSQL database.
- `data/uploads/` is created when the first photo is uploaded.
- `.env` stores local environment variables and is excluded from Git.
- `.env.example` lists the PostgreSQL and Telegram configuration keys without credentials.
- `server.js` serves the site and admin UI, and handles admin login, content, and photo APIs.
- `auth.js` implements visitor accounts: registration, e-mail confirmation, sign-in, password reset (`/api/auth/*`).
- `public/auth.js` is the sign-in / registration window on the homepage.
- PostgreSQL stores the site's content in the `site_content` table, and visitor accounts in `users`, `email_codes`, and `user_sessions` (created automatically on first start).
- `openapi.json` describes the HTTP API, and Swagger UI is available at `/api-docs`.
- `package.json` defines the local start command.
- `README.md` contains setup and security notes.

## Start the site

Use Node.js 18 or newer and PostgreSQL. Create a database and configure its connection string in `.env`:

```sh
createdb tourist_site
```

Set `DATABASE_URL` in `.env` to a PostgreSQL connection URL for that database (see `.env.example`). The PostgreSQL user must be allowed to connect and create tables. On its first start, the server creates `site_content` and imports `data/content.json` only if the table has no content yet. After that, PostgreSQL is the source of truth; admin edits are saved there.

Start the server from this project folder:

```sh
ADMIN_PASSWORD='' npm start
```

The local admin password is `12345`. To use a different password, set `ADMIN_PASSWORD` to a value of at least 5 characters before starting the server. Keep the server running, then open the public website at <http://127.0.0.1:4173> and click **Admin** (or open <http://127.0.0.1:4173/admin>). Do not open the HTML files directly or use a static-file preview server; editing and saved content both use this local server.

Browse and try the documented API at <http://127.0.0.1:4173/api-docs>. The raw OpenAPI specification is at <http://127.0.0.1:4173/api-docs/openapi.json>. Admin endpoints require signing in and keeping the session cookie; write operations also require a same-origin request.

## Visitor accounts (register / sign in with e-mail)

The **Sign in** button in the header opens a window with these procedures:

| Procedure | What happens |
| --- | --- |
| Register | Name, surname, e-mail, password (min. 8 characters, with a letter and a number). A 6-digit code is e-mailed. |
| Confirm e-mail | The code (valid 10 minutes, 5 tries) confirms the address and signs the visitor in. "Send a new code" works once a minute. |
| Sign in | E-mail + password. If the e-mail is not confirmed yet, a new code is sent and the confirm step opens. |
| Forgot password | A reset code is e-mailed; the visitor enters it with a new password. All devices are signed out. |
| Account | Shows who is signed in, lets the visitor change their password (other devices are signed out), and sign out. |

After signing in, the consultation form at the bottom of the page is pre-filled with the visitor's name and surname. The admin panel keeps its own separate password.

Security notes: passwords are hashed with scrypt and never stored in plain text; sessions are stored as hashes in PostgreSQL (30 days, `HttpOnly` cookie); codes are stored as hashes; sign-in, registration, and code requests are rate limited; the forgot-password and resend forms never reveal whether an e-mail is registered.

### Set up e-mail sending

Install the new dependency once:

```sh
npm install
```

Then fill in the SMTP keys in `.env` (see `.env.example`). Gmail example (use a Google *App password*, not your normal password):

```sh
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=you@gmail.com
SMTP_PASS=your-16-character-app-password
MAIL_FROM="Travel Horizon <you@gmail.com>"
```

If `SMTP_HOST` is empty, no e-mail is sent and the 6-digit codes are printed in the terminal where `npm start` is running. This is handy for development. When `NODE_ENV=production` and SMTP is not configured, registration returns an error instead of printing codes.

The API is documented in Swagger under the **Accounts** tag at <http://127.0.0.1:4173/api-docs>.

For Telegram configuration, put your bot token in `TELEGRAM_BOT_TOKEN` and the destination chat ID in `TELEGRAM_CHAT_ID` in `.env`. The consultation form at the bottom of the homepage sends the visitor's name, surname, phone number, and selected destination to that chat. Keep the token private; it is only used by the server.

The server intentionally listens only on `127.0.0.1`. This prototype is not a public multi-user deployment: anyone with access to this computer and the password can edit the site. Photo uploads accept JPEG, PNG, and WebP up to 8 MB. Do not expose it to the internet. A hosted version needs HTTPS, persistent user accounts and roles, production-grade password hashing, backups, and a deployment workflow that publishes approved content safely.