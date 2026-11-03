SCHOOL TERMINAL SHARED LOGIN — NETLIFY

FILES
- index.html: your existing School Terminal design, with the password check connected to the server.
- login.html: central sign-in page used by the other sites.
- netlify/functions/auth.mjs: server-side authentication.
- netlify.toml: routes /api/auth to the function.
- package.json: installs Netlify Blobs.
- auth.js: reusable protection script for each other website.

1) CENTRAL SCHOOL TERMINAL DEPLOY
Upload/commit ALL files in this folder to the GitHub repository connected to
https://schoolterminal.netlify.app. Keep the netlify/ folder at the repository root.
Netlify build settings: build command can be blank; publish directory is ".".
Netlify will install package.json dependencies and deploy the function.

2) SET THE PASSWORD
In Netlify, open the School Terminal site:
Site configuration > Environment variables (or Environment variables)
Add:
AUTH_PASSWORD = your chosen password
Save, then trigger a fresh deploy. Do not put the password in GitHub.

3) OTHER THREE REPOSITORIES
Copy auth.js into the root of each repository:
- 3kh0g.netlify.app
- schoolported.netlify.app
- monkeyg2.netlify.app

Add this line as early as possible in each site's <head>, before its page content:
<script src="/auth.js"></script>

Important: if a site has a restrictive Content Security Policy, allow scripts and fetch connections to https://schoolterminal.netlify.app.
For 3kh0g, the /projects page still loads /auth.js from the site root because the src begins with /.

4) VERIFY
- Open each site in a private/incognito window.
- It should redirect to School Terminal login.
- Enter the password once.
- It should return to the original page.
- Open the other protected sites in the same browser; they should load without asking again.

5) LOG OUT
Call this from a button click on any protected site:
SchoolTerminalAuth.logout()

SECURITY / LIMITS
- This uses a central HttpOnly cookie on schoolterminal.netlify.app plus one opaque session token stored per protected site's origin.
- Each protected site's token is checked against the central Netlify Function.
- The session remains valid until logout or the site's session record is deleted. Clearing a site's browser data removes that site's stored token.
- For a global logout, the logout function revokes the shared server-side session, so tokens on the other sites stop verifying too.
- Only the exact four origins in the function's allowlist are accepted. If you change a Netlify site URL, update the allowlist in auth.mjs and login.html.
- This protects access through the website UI; it cannot prevent someone from viewing public static files directly or bypassing client-side restrictions with developer tools.
- Configure AUTH_PASSWORD before testing. Never commit the password itself.
