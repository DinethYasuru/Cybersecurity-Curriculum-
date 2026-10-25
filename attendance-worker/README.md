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
5. Sign in with the main password (leave the mobile number empty). Then give each facilitator a password again under **Facilitators**.
6. Send the address to Claude so it becomes the page's built-in server for every phone.

Facilitator passwords and students' profile keys don't move. Set the passwords again, and students ask for a new key.

## Later

- **Unlock sign-in or sign everyone out:** Setup › Cloudflare server tools.
- **Backups:** Settings › Backups. Copies stay on the server (newest 30). Turn on the nightly copy to make one at 10 pm Sri Lanka time. Download the `.json` now and then to keep a copy yourself.
- **Off-site check-ins:** while Live QR is open during class, the server learns the classroom network. A check-in from another network (mobile data, or a friend at home) gets an "off-site" tag in Live QR and Register and shows under "Worth a look" on the Dashboard. Only a short fingerprint of the network is kept, never the address. This only works on Cloudflare, because the Google server can't see networks.
- **Is the update live?** Open the Worker's address in a browser. It shows `"version": N`, which should match `SERVER_VERSION` in `attendance-server.js`. If it's behind, check **Deployments** for a failed build. Also check **Settings › Build**: the production branch must be the repository's default branch, and the build watch paths must include `*`.
- **Try it on your computer:** `npm install`, put `SETUP_KEY=something-long` in `.dev.vars`, then run `npx wrangler dev`.

## Many classes (server version 16)

One server now runs every class at the American Corner.

- **Each class has its own database** (its own students, IDs, schedule, QR and settings). The Cyber Security class keeps its original database, so nothing is copied or lost.
- **The Corner** keeps what classes share: the class list, people (one person per mobile number, in any number of classes), facilitator accounts, and each facilitator's role in each class.
- On the first request after this update, the Corner learns the Cyber Security class, its main password, its facilitators (with their passwords) and its students. Nobody has to sign up again.
- **Students:** the Live QR link carries the class (`&k=english`). A typed code finds its class on its own. With no QR and two classes open, the student taps their class. Someone from another class joins with one tap and keeps their name. My attendance shows every class.
- **Facilitators** sign in once and switch class at the top. The **Corner admin** (main password, or a facilitator with the Corner admin box ticked) sees the American Corner page: today in every class, adding and archiving classes, who teaches where, and everyone who attends.
- A new class gets an ID prefix from its name (English gives ENG-0001). Set its days and times under Settings after opening it.
- The Google Sheet server stays single-class.

## Data safety (server version 17)

- Every request to a class runs as one transaction: all its changes are saved together, or none are.
- Where a request came from and who sent it are never shared between requests that run at the same time.
- A class's student list carries a version, so a late, older copy can't undo a newer change in the Corner.
- A new name or number reaches a person's other classes first. The Corner records it only after each class accepted it.
- Wrong passwords are counted per number and per internet address. A browser that signed in before has its own count.
- Wrong server keys are counted once for the whole Corner.
- Backups are stored in pieces, so a big class with photos still backs up.

## Coordinator and facilitators (server version 18)

- **Coordinator:** whoever signs in with the main password. The coordinator adds, archives and deletes classes, and makes and deletes facilitator accounts. In every class the coordinator can look but not change anything.
- **Starter accounts:** the coordinator makes an account with a mobile number, a simple starter password (6 or more characters), and the class and role it belongs to. The page writes a WhatsApp message to send.
- **First sign-in:** the facilitator must add their name and an optional photo, and choose their own password (8 or more characters), before anything else.
- **Lead facilitator:** can change settings in their class and the roles of the others there. Only the coordinator makes or deletes accounts.

## Admin and coordinator accounts (server version 19)

- **Admin:** whoever signs in with the main password (mobile number empty). No limits: every class, the Live QR, every change, and coordinator accounts. The main password changes only in Setup › Cloudflare server tools, with SETUP_KEY.
- **Coordinator:** a real account with a mobile number. Only the admin makes, resets or deletes one (American Corner › Add a coordinator). A coordinator sees every class, adds and deletes classes, and makes and deletes facilitator accounts. Inside a class a coordinator only looks: no changes, no Live QR, and the server never sends them the QR key.
- A coordinator signs in once with a starter password, then adds their name, optional photo and own password. After that they change their name, number, photo and password under My account.

## Users page

The admin and coordinators have a **Users** page with every coordinator, facilitator and student in one list (filter and search). From it you make accounts with a starter password and a WhatsApp message, change the classes and roles of each facilitator, give a new starter password, turn sign-in off, or delete an account. Only the admin makes or changes coordinators. Students are listed with their classes and IDs; their details change in a class under Students. The American Corner page now holds only the classes.

## Menus by role and admin password (server version 20)

- Each person sees only what they can use: facilitators see their class; leads also see Class tools (Settings, Activity log, Operations); coordinators see American Corner (Overview, Users) and a view-only class; the admin sees all.
- Accounts are made only on the Users page. A class's Team page lists who runs it and lets the lead change roles.
- The sign-in card has **Sign in as admin** (main password, no number).
- The admin changes the main password under **My account** with the current password. Other admin sign-ins end; facilitators and coordinators stay signed in. Setup › Cloudflare server tools still works if the password is forgotten.

## Danger zone (server version 21)

Only the admin (main password) sees **Danger zone** under American Corner. It asks for the main password again and stays unlocked for 15 minutes in that tab only (never saved). Five wrong passwords lock it for 15 minutes.

- **Prune old data:** activity log older than N days, all but the newest N backups in each class, old Recent changes, expired sign-ins and caches, used or old profile key requests, and enrolments, roles and people left behind by deleted classes or accounts. Students, attendance and accounts are never pruned.
- **Critical steps:** sign everyone out (type SIGN OUT), unlock sign-in, delete archived classes (type DELETE), new check-in codes for a class, clear a class's attendance for a new term (type the class name; students, team and settings stay).
- **Data editor:** pick the American Corner database or any class, pick a table, search and page through rows, tap a cell to change it, delete or add rows. Photos and backups are too long to edit here.
- **SQL:** runs on the database picked. SELECT shows up to 500 rows; anything that writes asks first.

A class is backed up before its first change (at most once every 10 minutes, and always before clearing attendance). Every change is listed under Recent changes. After a change to a class's students, the American Corner's people list follows.

## Branches, speed and checks (server version 22)

- **Branches.** Every American Corner branch runs this same code with its own Worker (deploy a copy under a new name, set its SETUP_KEY and main password). Each Worker has its own Durable Objects, so a class with the same name (even the same short id, like `cyber`) in two branches is two separate databases: students, accounts, attendance, staff and passwords never mix. A phone used with two branches keeps each branch's sign-in, logo and class choice apart too. The admin sets the branch's name and logo under American Corner › Branch. Students and staff see them at the top left, on printed day sheets and in downloads. Other copies of the page pick up a change within a minute.
- **Students' first screen.** The Corner keeps each class's hours, extra windows and cancelled days. A student who opens the page without a class QR asks only the classes that may be open now, so many classes no longer hit Cloudflare's per-request limit.
- **Sign out everywhere** (Setup) ends every sign-in in one call. New check-in codes for a class are in the Danger zone.
- **Faster.** Each copy of the Worker keeps the class list for a minute. The page's built-in logos are smaller (the page downloads 38% less) and it opens the line to the server while it loads.
- **Coordinators** can download a class's whole record (.json) from Reports › Export, but still change nothing.
- **Danger zone:** a wrong password makes the next try wait 2, 4, 8 … up to 60 seconds, instead of a 15-minute lock.
- **Checks.** `.github/workflows/attendance-tests.yml` runs on every pull request: the page and server must parse, and `test/server.test.cjs` runs against a local Worker. Run it yourself with `npm test` while `wrangler dev` is running.

## Students find their class (server version 23)

- The live QR already names its class, so scanning it with the phone camera goes straight to that class.
- Opened without a QR link while many classes are open, the page asks for the mobile number first. The server checks only that student's own classes that may be open now, so it stays fast with hundreds of classes. A typed code picks the right one of them.
- The class list shows only when the number can't decide: two of their own classes open at once (just those two), or a new student with no QR. The list has a search box when it is long.
- The in-app scanner keeps the class the QR names.

## Student app accounts (server version 24)

Students now sign in to the app before they check in. This is on by default. The admin can turn it off under **Student requests**.

1. On the check-in page the student taps **Ask for a key** and sends their number and name.
2. The admin (or a coordinator) sees it under **Student requests › Sign-in keys**, checks who it is, and taps **Send on WhatsApp**. The message has a link that opens the app with the key filled in. A key works once, within 7 days. **Give a key without a request** makes one for any number. The admin can also let the **WhatsApp helper** on their laptop send the keys automatically, slowly and within limits the server keeps: see [whatsapp-helper/README.md](../whatsapp-helper/README.md).
3. The student chooses their own password. With **Keep me signed in on this phone** ticked, the phone stays signed in (180 days from the last use). A new password signs out their other phones.

Once signed in, a student:
- marks attendance by scanning the QR or typing its code. The code decides the class: their own open classes first, then any open class (they join it, if that class lets students register).
- sees every class they attend, with their record in each.
- sends excuses for a missed day or a coming one. These go to that class's facilitators under **Inbox › Excuses from students**. Accepted ones become excused absences.
- changes their name and photo (in every class at once) or their password, and signs out.
- taps **Records missing?** to tell the admin about an old number.

**Records missing** requests: **Move records** (admin only) gives the old number's student IDs the new number in every class. Where the student had registered again with the new number, the two IDs become one: the older ID keeps every check-in and excuse. The old number's app account stops working. Also available as **Move records without a request**.

Before anything changes (server version 25), **Move records** and **Mark done** check both numbers again and show them side by side: the name, the app account and every class list each number is on, with a warning when the names differ. **Mark done** on a records request moves the records when the old number is still on a class list; the server refuses a plain "done" in that case. When the old number is on no list, it says so and only marks the request done.

The app shows the student's name from the class lists (server version 26). The name typed when asking for a key is used only until the number is on a class list, so a name the admin fixes in **Students**, or one a move brings, reaches the app the next time it opens.

New Corner tables: `accounts`, `areq` (sign-in and help requests), `xreq` (excuses sent from the app).

## Security update: change log and restore points (server version 27)

Students in the cyber security class will try to break in, so this version was checked the way a student attacker would and hardened. The full findings are in the pull request.

**Change log** (American Corner › Change log, admin only)
- Every change in every database is recorded: who made it (name and role), when, from which internet address, which row, and what each field was before and after. This covers changes made in the page, by students in the app, in the Danger zone (editor and SQL), by imports, restores and Setup.
- Sign-ins and failed tries are listed too. Failed tries keep the full address; a student's own changes keep only the first half of it (like 112.134.x.x).
- Passwords, keys, codes and photos are never written into the log, only that they changed.
- The log can only grow. The database refuses to edit or delete its rows, the Danger zone can't open or name it, and every entry is sealed to the one before it with the SETUP_KEY secret. **Check the whole log** finds any entry that was changed or removed some other way.
- **CSV** downloads the entries shown.

**Restore points** (Danger zone › Restore points)
- A restore point is a full copy of one database: a class, or the American Corner (classes, people, accounts, passwords, roles).
- One is made every night at 10 pm (always on now), before Danger zone changes, before clearing a term, before each restore, and once automatically on the first request after this update ("Restore point before the security update"). The newest 30 per database are kept.
- **Make a restore point of everything** copies the Corner and every class now, with a name you choose.
- **Go back to this** (type RESTORE) puts that database back exactly as it was. A restore point of just before is made first, so going back can be undone. The activity log and the change log are never rolled back, and everyone stays signed in.
- Restore points can't be edited or deleted by hand in the Danger zone (Prune still keeps the newest N, and is logged).

**Sign-in and passwords**
- Wrong server keys are counted per internet address (10 lock that address for 15 minutes, 200 from everywhere lock Setup). Before, 10 wrong keys from anyone locked the admin out of Setup.
- A phone that signed in to the student app before has its own count of wrong passwords, so a classmate can't lock a student out by typing wrong passwords for their number.
- The student app gives the same answer for a wrong password whether or not the number has an account.
- New student passwords need 8 characters with letters, not only numbers, not the mobile number and not a common password.
- A student can save their profile at most 30 times an hour.
- A link or QR that points the page to another server (`?s=`) shows a red warning to students, and asks before any password (student or staff) goes there.
