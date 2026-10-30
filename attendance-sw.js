/* Class reminders for the attendance app (attendance.html): shows the notification the attendance server sends
   the evening before a class, and opens the app when it is tapped.
   There is no fetch handler on purpose: pages always load from the network and nothing is cached here. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (x) { d = { b: e.data ? e.data.text() : '' }; }
  // only a page of this site opens from a notification
  let url = new URL('attendance.html', self.registration.scope.replace(/attendance$/, ''));
  try { const u = new URL(String(d.u || 'attendance.html'), url); if (u.origin === self.location.origin) url = u; } catch (x) {}
  e.waitUntil(self.registration.showNotification(String(d.t || 'Class reminder').slice(0, 80), {
    body: String(d.b || '').slice(0, 240), icon: 'attendance-icon-192.png', badge: 'attendance-icon-192.png',
    tag: String(d.g || 'class').slice(0, 60), data: { url: url.href }
  }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || 'attendance.html';
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    for (const c of list) if (c.url.split(/[?#]/)[0] === url.split(/[?#]/)[0] && 'focus' in c) return c.focus();
    return self.clients.openWindow(url);
  }));
});
