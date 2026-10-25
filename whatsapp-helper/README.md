# WhatsApp helper: send app keys automatically

When a student taps **Ask for a key**, this helper sends them their key on WhatsApp, from WhatsApp Web on your laptop. No SMS, no cost. You don't press **Send on WhatsApp** for each one any more.

It runs only while your laptop is on and this window is open. Anything it can't send stays in **Student requests** for you to send by hand, as before.

## Read this first: WhatsApp can ban a number

WhatsApp blocks numbers that look like bulk senders, especially when they message people who never saved the number. The helper is slow on purpose to stay safe:

- The server lets it send at most **10 an hour and 40 a day** (you pick lower; the defaults are 6 an hour and 20 a day), **at least 2 minutes apart** (default 4), and only **between 07:30 and 20:30**.
- It sends one at a time, "types" for a few seconds first, and waits a random 1 to 3 minutes after each one.
- It sends only to the number that asked for the key, and (by default) only if that number is on a class list.

Even so, a ban can happen. **Use a spare SIM if you can** (a cheap prepaid number with WhatsApp on an old phone), not your personal number. Tell students to save that number, and ask them to reply "OK" when the key arrives: replies make the number look normal to WhatsApp.

## What it can and can't do

The helper has its own key, made in the attendance app. With it, the helper can only:

1. take the next sign-in key waiting to be sent (the number, the first name and the message), and
2. tell the server it was sent (or why not).

It can't see students, attendance, photos or anything else, and it can't sign in as you. Every key it takes, every message it sends and every wrong helper key shows in **Change log** as *WhatsApp helper*. If the key leaks, make a new one (the old one stops working at once).

## Set it up (once, about 15 minutes)

### 1. Install Node.js

Download the **LTS** version from <https://nodejs.org> and install it with the default options. To check: open **Command Prompt** (Windows) or **Terminal** (Mac) and type `node -v`. You should see `v18` or higher.

### 2. Get the helper folder

On GitHub, open the repository, **Code › Download ZIP**, unzip it, and keep the `whatsapp-helper` folder somewhere easy, like `Documents\whatsapp-helper`.

### 3. Install the helper

In Command Prompt / Terminal:

```
cd Documents\whatsapp-helper
npm install
```

(On a Mac: `cd ~/Documents/whatsapp-helper`.) This downloads WhatsApp Web's browser too, so it takes a few minutes the first time.

### 4. Make the helper key

1. Open the attendance app and sign in with the **main password** (admin).
2. Go to **Student requests**. Under the switches, open **Helper settings**.
3. Check the limits and hours, then tap **Save**.
4. Tap **Make helper key**. The key is shown once and copied. It starts with `wa_`.

### 5. Put the key in config.json

In the `whatsapp-helper` folder, copy `config.example.json` to a new file named `config.json`. Open it in Notepad and paste the key:

```json
{
  "server": "https://cyber-attendance.dinethyasuru.workers.dev",
  "helperKey": "wa_...your key...",
  "maxPerHour": 6,
  "maxPerDay": 20
}
```

`maxPerHour` and `maxPerDay` are this laptop's own limits on top of the server's. Keep `config.json` private; it is not uploaded to GitHub.

### 6. Start it and link WhatsApp

```
npm start
```

A QR code appears in the window. On the phone with the sending number: **WhatsApp › Settings › Linked devices › Link a device**, and scan it. When the window says **WhatsApp is ready**, it's working. Next time it starts without a QR.

### 7. Turn it on

Back in **Student requests**, tick **Send keys automatically from WhatsApp Web** and confirm. The line next to it shows **Helper running** and how many it sent today.

## Every class day

1. Open Command Prompt / Terminal, `cd` to the folder, and type `npm start`.
2. Leave the window open (you can minimise it). **Ctrl+C** stops it.

The window tells you what it is doing: waiting, sending, or why it is not sending (outside the hours, a limit reached, turned off).

## When something goes wrong

| You see | Do this |
|---|---|
| `The helper key is not right` | Make a new key in Helper settings and put it in `config.json`. |
| `Sending is turned off` | Tick the switch in Student requests. |
| `has no WhatsApp` / in Student requests: *WhatsApp helper could not send it* | Send that key by hand with **Send on WhatsApp** or **Copy message**. The helper won't try that one again. |
| `WhatsApp disconnected` or the QR keeps coming back | Close the window, delete the `.wwebjs_auth` folder, `npm start`, and scan again. |
| WhatsApp says the number is banned | Stop the helper (untick the switch), send keys by hand, and appeal in the WhatsApp app. Use another number for the helper. |
| It stopped working after a WhatsApp update | In the folder, run `npm update`, then `npm start`. |

To stop it for good: untick the switch, and tap **Stop the helper key**. On the phone, remove the laptop under **Linked devices**.
