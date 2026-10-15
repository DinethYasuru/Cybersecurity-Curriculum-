# Attendance server on Cloudflare (free)

This folder runs the class attendance server as a Cloudflare Worker on the free plan. It uses the same logic as `../attendance-server.js` (the Google Apps Script version), but keeps the data in a Durable Object's own SQLite database instead of a Google Sheet.

- **Free plan:** 100,000 requests a day. A class day uses about 4,000.
- **No time limit, no card:** the free plan doesn't expire and isn't a trial.
- **Faster than Apps Script:** no 1,000-row Sheet limit.
- **Auto-deploy:** every push to the repository's default branch redeploys the Worker automatically, so there is no "New version" step.

## Set up (once, about 10 minutes)

1. Make a free account at [dash.cloudflare.com](https://dash.cloudflare.com/sign-up).
2. Go to **Workers & Pages › Create › Import a repository**.
3. Connect GitHub and pick **Cybersecurity-Curriculum-**. Then set:
   - **Project name:** `cyber-attendance`
   - **Production branch:** `claude/ecstatic-heisenberg-ft5ub0`
   - **Root directory (Advanced settings › Path):** `attendance-worker`
   - Leave the build command empty, and leave the deploy command as `npx wrangler deploy`.
4. Click **Deploy**.
5. When it's done, open the Worker. Go to **Settings › Variables and Secrets › Add**. Choose type **Secret**, name it `SETUP_KEY`, and give it a long random value (12+ characters). Keep this key private. Click **Deploy**.
6. Copy the Worker's address. It looks like `https://cyber-attendance.<your-name>.workers.dev`.

## Move in

On the attendance page, open **Setup › Cloudflare server tools**.

1. Paste the address and the server key, then press **Check**.
2. Set the **main password**.
3. While you are still signed in to the Google Sheet server on this browser, press **Copy from the signed-in Google server**. You can also use **Load a backup file**, with a `.json` from Settings › Download full backup.
4. Paste the address under **Connect the server**, then press **Connect**.
5. Sign in with the main password (leave the mobile number empty). Then give each instructor a password again under **Instructors**.
6. Send the address to Claude so it becomes the page's built-in server for every phone.

Instructor passwords and students' profile keys don't move. Set the passwords again, and students ask for a new key.

## Later

- **Unlock sign-in or sign everyone out:** Setup › Cloudflare server tools.
- **Backups:** Settings › Backups. Copies stay on the server (newest 30). Turn on the nightly copy to make one at 10 pm Sri Lanka time. Download the `.json` now and then to keep a copy yourself.
- **Off-site check-ins:** while Live QR is open during class, the server learns the classroom network. A check-in from another network (mobile data, or a friend at home) gets an "off-site" tag in Live QR and Register and shows under "Worth a look" on the Dashboard. Only a short fingerprint of the network is kept, never the address. This only works on Cloudflare, because the Google server can't see networks.
- **Try it on your computer:** `npm install`, put `SETUP_KEY=something-long` in `.dev.vars`, then run `npx wrangler dev`.
