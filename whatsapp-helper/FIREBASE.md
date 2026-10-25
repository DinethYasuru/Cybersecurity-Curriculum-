# Firebase key queue

The attendance server puts the sign-in keys, one at a time, into your Firebase Realtime Database. Your own WhatsApp side reads the key, sends it, and sets a flag. Then the server puts in the next one.

Database: `https://attendance-whatsap-keyque-default-rtdb.firebaseio.com` (already in `attendance-worker/wrangler.toml`).

## The slot

There is only ever one key in the database, at `/keyQueue/current`:

```json
{
  "rid": "6e8de6ac32da",
  "claim": "a872afeb067dbd00",
  "phone": "94771234567",
  "name": "Sahan",
  "key": "Q5Q7-WNB5",
  "link": "https://.../attendance.html?key=0771234567.Q5Q7WNB5",
  "text": "Hi Sahan, your key for the class attendance app: ... (the full WhatsApp message with the link)",
  "flag": "pending",
  "at": 1792940326814
}
```

Your reader:

1. watches `/keyQueue/current`,
2. when `flag` is `"pending"`, sends `text` to `phone` on WhatsApp (or builds its own message from `name`, `key` and `link`),
3. sets `flag` to `"sent"`, or to `"failed"` with a short `reason` (for example `"no WhatsApp on this number"`; a number with no WhatsApp is not tried again).

Change only `flag` and `reason`. Leave `rid` and `claim` as they are: the server only accepts a slot it put there itself.

It is realtime, with no hours, limits or waiting:

- When a student asks for a key (or you make one in Student requests), it goes into the slot at once, if the slot is empty.
- When your reader sets the flag, it should also call the Worker once: `POST https://cyber-attendance.dinethyasuru.workers.dev` with body `{"action":"fbPoke"}`. The server then marks the request **Sent** in Student requests, empties the slot, and puts the next key in straight away.
- If the reader doesn't call, the server still looks once a minute.

`/keyQueue/status` says what is happening (a key is waiting, nothing to send, turned off). The hours and limits in Helper settings are only for the laptop helper. Every key put in and every one sent is in the **Change log** as *Firebase queue*.

## Set it up (once)

1. **The server's secret.** Firebase console › Project settings (gear) › **Service accounts** › **Database secrets** › Show, and copy it. In Cloudflare: Workers & Pages › **cyber-attendance** › Settings › **Variables and Secrets** › Add, type **Secret**, name `FIREBASE_SECRET`, paste, Deploy. Never put it in GitHub or in your reader.
2. **A sign-in for your reader.** Firebase console › Build › **Authentication** › Get started › Email/Password › Enable. Under Users, **Add user** (any email and a long password). Copy its **User UID**.
3. **Rules.** Realtime Database › **Rules**, paste this with your reader's UID, and Publish. Only your reader can read the slot, and it can only change `flag` and `reason`. (The server's secret is not limited by rules.)

```json
{
  "rules": {
    ".read": false,
    ".write": false,
    "keyQueue": {
      ".read": "auth != null && auth.uid === 'PASTE_READER_UID'",
      "current": {
        "flag": { ".write": "auth != null && auth.uid === 'PASTE_READER_UID' && data.exists() && (newData.val() === 'sent' || newData.val() === 'failed')" },
        "reason": { ".write": "auth != null && auth.uid === 'PASTE_READER_UID' && data.parent().exists() && newData.isString() && newData.val().length <= 80" }
      }
    }
  }
}
```

4. **Turn it on.** In the attendance app, **Student requests**: tick **Send keys automatically**. The line next to it shows the Firebase queue's state. Within a minute the first key appears in `/keyQueue/current`.

## A reader in a few lines (Firebase JS SDK)

```js
import { initializeApp } from 'firebase/app';
import { getAuth, signInWithEmailAndPassword } from 'firebase/auth';
import { getDatabase, ref, onValue, update } from 'firebase/database';

const app = initializeApp({ apiKey: 'from Project settings › General', databaseURL: 'https://attendance-whatsap-keyque-default-rtdb.firebaseio.com' });
await signInWithEmailAndPassword(getAuth(app), 'reader@example.com', 'the reader password');
const slot = ref(getDatabase(app), 'keyQueue/current');
onValue(slot, async snap => {
  const job = snap.val();
  if (!job || job.flag !== 'pending') return;
  try {
    await sendOnWhatsApp(job.phone, job.text);   // your WhatsApp side
    await update(slot, { flag: 'sent' });
  } catch (e) {
    await update(slot, { flag: 'failed', reason: String(e.message).slice(0, 80) });
  }
  // tell the Worker to look now: the next key comes straight away
  fetch('https://cyber-attendance.dinethyasuru.workers.dev', { method: 'POST', body: JSON.stringify({ action: 'fbPoke' }) });
});
```

WhatsApp can block a number that messages many people who never saved it. The queue sends as fast as your reader does, so a spare SIM is the safest.
