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

    const bcrypt = require('bcryptjs');

    // ==========================================
    // Authentication Routes
    // ==========================================
    app.post('/api/auth/register', async (req, res) => {
      const { name, email, password, role, photoURL } = req.body;
      
      const query = { email: email };
      const existingUser = await usersCollection.findOne(query);
      if (existingUser) {
        return res.status(400).send({ message: 'User already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const credits = role === 'Supporter' ? 50 : 20;

      const newUser = {
        name,
        email,
        password: hashedPassword,
        role,
        photoURL: photoURL || '',
        credits,
        createdAt: new Date(),
      };

      const result = await usersCollection.insertOne(newUser);
      
      // Generate Token
      const secret = new TextEncoder().encode(process.env.ACCESS_TOKEN_SECRET);
      const token = await new SignJWT({ email: newUser.email, role: newUser.role })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('7d')
        .sign(secret);

      res.send({ 
        token, 
        user: { 
          _id: result.insertedId,
          name: newUser.name, 
          email: newUser.email, 
          role: newUser.role, 
          credits: newUser.credits,
          photoURL: newUser.photoURL
        } 
      });
    });

    app.post('/api/auth/login', async (req, res) => {
      const { email, password } = req.body;
      
      const user = await usersCollection.findOne({ email: email });
      if (!user) {
        return res.status(401).send({ message: 'Invalid credentials' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).send({ message: 'Invalid credentials' });
      }

      const secret = new TextEncoder().encode(process.env.ACCESS_TOKEN_SECRET);
      const token = await new SignJWT({ email: user.email, role: user.role })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('7d')
        .sign(secret);

      res.send({ 
        token, 
        user: { 
          _id: user._id,
          name: user.name, 
          email: user.email, 
          role: user.role, 
          credits: user.credits,
          photoURL: user.photoURL
        } 
      });
    });

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
