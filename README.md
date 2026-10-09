# Client app launch page (private)

The Ramage Law Group client app launch page, hosted on Vercel behind Microsoft sign-in.
Only @ramagelawfirm.com accounts in the firm's Microsoft 365 tenant can open it or post notes.
Notes are stored as GitHub issues in this repo, posted by the server under each person's verified email.

## How it fits together

- `private/index.html`: the page. It is only served after sign-in, never as a public file.
- `api/app.js`: one Vercel function for Microsoft sign-in, the page, and the notes API.
- `public/`: the only publicly served files (the signed-out screen).
- `vercel.json`: routes and security headers.

## Setup

### 1. Microsoft Entra app registration
1. Entra admin center > App registrations > New registration.
2. Name: `RLG App Launch Page`. Supported account types: **this organizational directory only (single tenant)**.
3. Redirect URI: platform **Web**, `https://YOUR-VERCEL-DOMAIN/auth/callback` (add it after step 3 if you don't know the domain yet).
4. Certificates & secrets > New client secret. Copy the secret **Value**.
5. From Overview, copy the **Application (client) ID** and **Directory (tenant) ID**.
6. Optional, to limit it to specific people: Enterprise applications > this app > Properties > Assignment required = Yes, then add users or groups.

### 2. GitHub fine-grained token
GitHub > Settings > Developer settings > Fine-grained tokens > Generate new token.
Repository access: only `jdinsm-rlf/app-launch`. Permissions: **Issues: Read and write**.

### 3. Vercel
1. Add New > Project > import `jdinsm-rlf/app-launch`. Framework preset: **Other**. Leave build settings empty.
2. Environment variables:

| Name | Value |
| --- | --- |
| `ENTRA_TENANT_ID` | Directory (tenant) ID |
| `ENTRA_CLIENT_ID` | Application (client) ID |
| `ENTRA_CLIENT_SECRET` | Client secret value |
| `SESSION_SECRET` | A long random string, for example from `openssl rand -base64 48` |
| `GITHUB_TOKEN` | Fine-grained token from step 2 |
| `GITHUB_REPO` | `jdinsm-rlf/app-launch` |
| `ALLOWED_EMAIL_DOMAIN` | `ramagelawfirm.com` |
| `ADMIN_EMAILS` | Comma-separated emails that can change note status, for example `joseph@ramagelawfirm.com` |
| `BASE_URL` | Optional. Set it if you add a custom domain, for example `https://launch.ramagelawfirm.com` |

3. Deploy, then make sure the Entra redirect URI matches the deployed domain.

### 4. Lock the repo down
Make the repository private. That also turns off the old GitHub Pages copy. The root `index.html` is the old public version and can be deleted.

## Editing the page
- Content lives in `private/index.html`.
- `PAGE_UPDATES` (near the bottom): add an entry at the top each time the page changes.
- `DONE`: mark a checklist step done, for example `"s1-f1": "Joseph, Oct 10"`.

## Note status
Admins see a status menu on change requests and questions: Open, In progress, Done, Won't do.
It updates the GitHub issue (open, `in progress` label, closed as completed, or closed as not planned).
