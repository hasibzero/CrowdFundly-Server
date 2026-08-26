require('dotenv').config();
const { MongoClient, ServerApiVersion } = require('mongodb');
const bcrypt = require('bcryptjs');

const uri = process.env.MONGODB_URI;

// Admin account documented in the project README.
// The email is taken from the first entry of ADMIN_EMAILS so it always matches
// the allowlist the API uses when assigning the Admin role.
const ADMIN_EMAIL = (process.env.ADMIN_EMAILS || 'admin@crowdfundly.com')
  .split(',')[0]
  .trim()
  .toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const ADMIN_NAME = process.env.ADMIN_NAME || 'Admin';

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function seedAdmin() {
  if (!uri) {
    console.error('MONGODB_URI is not set. Add it to server/.env before seeding.');
    process.exit(1);
  }

  try {
    await client.connect();
    const db = client.db('crowdfundly');
    const usersCollection = db.collection('users');

    const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 12);

    // Upsert so re-running is safe: guarantees the account exists, has a known
    // password, and the Admin role — even if it was previously a Supporter.
    const result = await usersCollection.updateOne(
      { email: ADMIN_EMAIL },
      {
        $set: {
          name: ADMIN_NAME,
          password: hashedPassword,
          role: 'Admin',
        },
        $setOnInsert: {
          email: ADMIN_EMAIL,
          photoURL: '',
          credits: 0,
          createdAt: new Date(),
        },
      },
      { upsert: true }
    );

    if (result.upsertedCount > 0) {
      console.log(`Created admin user: ${ADMIN_EMAIL}`);
    } else {
      console.log(`Ensured Admin role for existing user: ${ADMIN_EMAIL}`);
    }
    console.log(`Login with  ${ADMIN_EMAIL}  /  ${ADMIN_PASSWORD}`);
  } catch (err) {
    console.error('Error seeding admin user:', err);
    process.exitCode = 1;
  } finally {
    await client.close();
  }
}

seedAdmin();
