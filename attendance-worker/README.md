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
- **Is the update live?** Open the Worker's address in a browser. It shows `"version": N`, which should match `SERVER_VERSION` in `attendance-server.js`. If it's behind, check **Deployments** for a failed build. Also check **Settings › Build**: the production branch must be the repository's default branch, and the build watch paths must include `*`.
- **Try it on your computer:** `npm install`, put `SETUP_KEY=something-long` in `.dev.vars`, then run `npx wrangler dev`.

## Many classes (server version 16)

One server now runs every class at the American Corner.

- **Each class has its own database** (its own students, IDs, schedule, QR and settings). The Cyber Security class keeps its original database, so nothing is copied or lost.
- **The Corner** keeps what classes share: the class list, people (one person per mobile number, in any number of classes), instructor accounts, and each instructor's role in each class.
- On the first request after this update, the Corner learns the Cyber Security class, its main password, its instructors (with their passwords) and its students. Nobody has to sign up again.
- **Students:** the Live QR link carries the class (`&k=english`). A typed code finds its class on its own. With no QR and two classes open, the student taps their class. Someone from another class joins with one tap and keeps their name. My attendance shows every class.
- **Instructors** sign in once and switch class at the top. The **Corner admin** (main password, or an instructor with the Corner admin box ticked) sees the American Corner page: today in every class, adding and archiving classes, who teaches where, and everyone who attends.
- A new class gets an ID prefix from its name (English gives ENG-0001). Set its days and times under Settings after opening it.
- The Google Sheet server stays single-class.
