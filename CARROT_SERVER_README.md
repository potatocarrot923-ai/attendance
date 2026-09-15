# Carrot Attendance shared API

The static page can work offline, but `server.py` adds shared local API storage for instructor login, attendance, and schedule changes.

## Start on Windows

Double-click `start_carrot_server.bat`, or run:

```powershell
python server.py
```

Then open `classroom.html` in the browser.

The normal server runs securely at `https://127.0.0.1:3443/classroom.html` and is locked to this computer.

To let friends use it on the same Wi-Fi, run `start_carrot_lan.bat`. They can open:

```text
https://192.168.254.123:3443/classroom.html
```

LAN mode is limited to the same Wi-Fi network and is not internet hosting. Chrome may show a certificate warning because the local certificate is not issued by a public certificate authority.

Because this uses a local self-signed certificate, Chrome may show a certificate warning the first time. The site and data remain local to this computer.

The server generates a strong instructor password on first start and saves it in `carrot_admin_password.txt`. If `CARROT_ADMIN_PASSWORD` is set before starting the server, that value is used instead.

- Username: `admin`

Password recovery sends the one-time code through Twilio. Configure these server environment variables before enabling recovery; none belong in the HTML file:

```text
CARROT_ADMIN_PHONE=09171234567
CARROT_TWILIO_ACCOUNT_SID=AC...
CARROT_TWILIO_AUTH_TOKEN=...
CARROT_TWILIO_FROM_NUMBER=+15005550006
```

The code is generated, delivered, rate-limited, and checked only by the server. It is never returned to the browser or shown on the laptop. The current API is intended for a trusted local network; production use still requires HTTPS, a real database, stronger user management, and audit logging.

## Public school deployment

For students on different networks, deploy this project to a managed HTTPS host such as Render using `render.yaml`. The host provides the public HTTPS URL while your laptop stays private. Set a strong `CARROT_ADMIN_PASSWORD` secret in the host dashboard and never upload `carrot_data.json`, `carrot_admin_password.txt`, or `certs/`.

Public mode refuses to start unless `CARROT_ADMIN_PASSWORD` is supplied by the host secret manager. Instructor login also requires the remote API on public and LAN hostnames; the development-only local PIN fallback is unavailable there.

Before real attendance use, replace local JSON storage with a managed database and add separate student authentication. Do not expose your home laptop with router port forwarding.

## Firebase package

The repository also includes `firebase.json`, `firestore.rules`, `firestore.indexes.json`, and `.firebaserc.example`.

These files provide:

- Firebase Hosting configuration with security headers
- Exclusion of local passwords, certificates, JSON data, and Python server files
- Firestore rules that deny browser reads and writes by default
- A project ID template without committing a real project identifier

Do not deploy the current page as a production attendance system by Hosting alone. The page still expects `/api/*` routes. The safe production architecture is Firebase Hosting plus Firebase Authentication and trusted server-side Cloud Functions that validate session codes, write attendance, and manage schedules with the Admin SDK. Firestore client rules should remain deny-by-default until those functions are connected.

Typical deployment after installing the Firebase CLI and creating a Firebase project:

```powershell
Copy-Item .firebaserc.example .firebaserc
# Replace YOUR_FIREBASE_PROJECT_ID in .firebaserc
firebase login
firebase use YOUR_FIREBASE_PROJECT_ID
firebase deploy --only hosting,firestore:rules
```

The resulting Hosting URL is the public student link. It will not work until the server-side `/api/*` functions are deployed as well.
