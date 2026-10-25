// Adds a made-up Firebase service account to .dev.vars for the server checks: its token_uri is the test's
// stand-in for Google (port 8799), which checks the signed JWT with the account's own public key.
const fs = require('fs'), crypto = require('crypto');
const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const sa = { type: 'service_account', project_id: 'ci', client_email: 'ci-queue@ci.iam.gserviceaccount.com',
  private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }), token_uri: 'http://127.0.0.1:8799/token' };
fs.appendFileSync(__dirname + '/../.dev.vars', 'FIREBASE_URL=http://127.0.0.1:8799\nFIREBASE_SERVICE_ACCOUNT=\'' + JSON.stringify(sa) + '\'\n');
