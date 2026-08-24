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

    // ==========================================
    // Campaigns Routes
    // ==========================================
    
    // Create a new campaign (Requires Creator role)
    app.post('/api/campaigns', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Creator' && req.decoded.role !== 'Admin') {
          return res.status(403).send({ message: 'Only creators can start campaigns' });
        }
        const newCampaign = req.body;
        newCampaign.createdAt = new Date();
        newCampaign.status = 'Pending';
        newCampaign.raised = 0; // Starts at 0
        
        const result = await campaignsCollection.insertOne(newCampaign);
        res.status(201).send({ ...newCampaign, _id: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Failed to create campaign', error: error.message });
      }
    });

    // Get all campaigns (Public view - only approved ones usually, but Admins see all)
    app.get('/api/campaigns', async (req, res) => {
      try {
        const { status, creatorEmail } = req.query;
        let query = {};
        if (status) query.status = status;
        if (creatorEmail) query.creatorEmail = creatorEmail;

        const campaigns = await campaignsCollection.find(query).sort({ createdAt: -1 }).toArray();
        res.send(campaigns);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch campaigns', error: error.message });
      }
    });

    // Get a specific campaign
    app.get('/api/campaigns/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const campaign = await campaignsCollection.findOne(query);
        if (!campaign) return res.status(404).send({ message: 'Campaign not found' });
        res.send(campaign);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch campaign', error: error.message });
      }
    });

    // Update campaign status (Admin approval)
    app.patch('/api/campaigns/:id/status', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Admin') {
          return res.status(403).send({ message: 'Only admins can approve campaigns' });
        }
        const id = req.params.id;
        const { status } = req.body; // 'Approved' or 'Rejected'
        
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: { status: status, updatedAt: new Date() },
        };
        const result = await campaignsCollection.updateOne(filter, updateDoc);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to update campaign', error: error.message });
      }
    });

    // Delete a campaign (Creator or Admin)
    app.delete('/api/campaigns/:id', verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const campaign = await campaignsCollection.findOne(query);
        
        if (!campaign) {
          return res.status(404).send({ message: 'Campaign not found' });
        }
        
        // Ensure user is the owner or an admin
        if (req.decoded.email !== campaign.creatorEmail && req.decoded.role !== 'Admin') {
           return res.status(403).send({ message: 'Forbidden access' });
        }
        
        const result = await campaignsCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to delete campaign', error: error.message });
      }
    });

    // ==========================================
    // Credits & Contributions Routes
    // ==========================================

    // Support a campaign
    app.post('/api/contributions', verifyToken, async (req, res) => {
      try {
        const { campaignId, amount, paymentMethod } = req.body;
        const userEmail = req.decoded.email;

        // Check user balance if using credits
        if (paymentMethod === 'Credits') {
          const user = await usersCollection.findOne({ email: userEmail });
          if (!user || user.credits < amount) {
            return res.status(400).send({ message: 'Insufficient credits' });
          }
          
          // Deduct credits from user
          await usersCollection.updateOne(
            { email: userEmail },
            { $inc: { credits: -amount } }
          );
        }

        // Add to campaign raised amount
        await campaignsCollection.updateOne(
          { _id: new ObjectId(campaignId) },
          { $inc: { raised: amount } }
        );

        // Record contribution
        const newContribution = {
          campaignId: new ObjectId(campaignId),
          supporterEmail: userEmail,
          amount,
          paymentMethod,
          date: new Date(),
          status: 'Completed'
        };
        const result = await contributionsCollection.insertOne(newContribution);
        
        res.status(201).send({ ...newContribution, _id: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Failed to process contribution', error: error.message });
      }
    });

    // Get user contributions
    app.get('/api/contributions', verifyToken, async (req, res) => {
      try {
        const query = { supporterEmail: req.decoded.email };
        const contributions = await contributionsCollection.find(query).sort({ date: -1 }).toArray();
        res.send(contributions);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch contributions', error: error.message });
      }
    });

    // ==========================================
    // Withdrawals Routes
    // ==========================================

    // Request Withdrawal (Creator)
    app.post('/api/withdrawals', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Creator') {
          return res.status(403).send({ message: 'Only creators can request withdrawals' });
        }
        
        const { creditsToWithdraw, paymentMethod, paymentDetails } = req.body;
        const userEmail = req.decoded.email;

        // Check user balance
        const user = await usersCollection.findOne({ email: userEmail });
        if (!user || user.credits < creditsToWithdraw) {
          return res.status(400).send({ message: 'Insufficient credits for withdrawal' });
        }

        // Deduct credits immediately (escrow)
        await usersCollection.updateOne(
          { email: userEmail },
          { $inc: { credits: -creditsToWithdraw } }
        );

        const newWithdrawal = {
          creatorEmail: userEmail,
          credits: creditsToWithdraw,
          amountUSD: creditsToWithdraw / 10, // Example conversion rate: 10 credits = $1
          paymentMethod,
          paymentDetails,
          status: 'Pending',
          requestDate: new Date(),
        };

        const result = await withdrawalsCollection.insertOne(newWithdrawal);
        res.status(201).send({ ...newWithdrawal, _id: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Failed to request withdrawal', error: error.message });
      }
    });

    // Get withdrawals (Admin views all, Creator views theirs)
    app.get('/api/withdrawals', verifyToken, async (req, res) => {
      try {
        let query = {};
        if (req.decoded.role === 'Creator') {
          query.creatorEmail = req.decoded.email;
        } else if (req.decoded.role !== 'Admin') {
          return res.status(403).send({ message: 'Forbidden access' });
        }
        
        const withdrawals = await withdrawalsCollection.find(query).sort({ requestDate: -1 }).toArray();
        res.send(withdrawals);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch withdrawals', error: error.message });
      }
    });

    // Process Withdrawal (Admin)
    app.patch('/api/withdrawals/:id/status', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Admin') {
          return res.status(403).send({ message: 'Only admins can process withdrawals' });
        }
        
        const id = req.params.id;
        const { status } = req.body; // 'Processed' or 'Denied'
        
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: { status: status, processedDate: new Date() },
        };
        const result = await withdrawalsCollection.updateOne(filter, updateDoc);
        
        // If denied, refund the credits to creator
        if (status === 'Denied') {
           const withdrawal = await withdrawalsCollection.findOne(filter);
           if (withdrawal) {
             await usersCollection.updateOne(
               { email: withdrawal.creatorEmail },
               { $inc: { credits: withdrawal.credits } }
             );
           }
        }
        
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to update withdrawal', error: error.message });
      }
    });

    // ==========================================
    // Admin Routes
    // ==========================================

    // Get all users
    app.get('/api/admin/users', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Admin') {
          return res.status(403).send({ message: 'Admin access required' });
        }
        const users = await usersCollection.find({}).toArray();
        res.send(users);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch users', error: error.message });
      }
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
