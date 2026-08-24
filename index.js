require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const { SignJWT, jwtVerify } = require('jose-cjs');

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

const uri = process.env.MONGODB_URI;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server
    await client.connect();
    
    // Database and Collections
    const db = client.db('crowdfundly');
    const usersCollection = db.collection('users');
    const campaignsCollection = db.collection('campaigns');
    const contributionsCollection = db.collection('contributions');
    const withdrawalsCollection = db.collection('withdrawals');
    const notificationsCollection = db.collection('notifications');

    // ==========================================
    // JWT Generation Endpoint
    // ==========================================
    app.post('/jwt', async (req, res) => {
      const user = req.body;
      const secret = new TextEncoder().encode(process.env.ACCESS_TOKEN_SECRET);
      const token = await new SignJWT(user)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(secret);
      res.send({ token });
    });

    // ==========================================
    // Middleware: Verify Token
    // ==========================================
    const verifyToken = async (req, res, next) => {
      if (!req.headers.authorization) {
        return res.status(401).send({ message: 'unauthorized access' });
      }
      const token = req.headers.authorization.split(' ')[1];
      try {
        const secret = new TextEncoder().encode(process.env.ACCESS_TOKEN_SECRET);
        const { payload } = await jwtVerify(token, secret);
        req.decoded = payload;
        next();
      } catch (err) {
        return res.status(401).send({ message: 'unauthorized access' });
      }
    };

    // ==========================================
    // Basic Routes Example
    // ==========================================
    app.get('/', (req, res) => {
      res.send('Crowdfundly Server is running!');
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
