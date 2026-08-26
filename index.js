require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const { SignJWT, jwtVerify } = require('jose-cjs');

const stripe = process.env.STRIPE_SECRET_KEY ? require('stripe')(process.env.STRIPE_SECRET_KEY) : null;


const app = express();
const port = process.env.PORT || 5000;

// Middleware
const clientUrl = process.env.CLIENT_URL || 'http://localhost:3000';
// Credit economy (per assessment spec):
//   Purchase:   $1 => 10 credits    (supporters buy credits)
//   Withdrawal: 20 credits => $1     (creators cash out earned credits)
const creditsPerUsdPurchase = 10;
const creditsPerUsdWithdraw = 20;
// No signup bonus — every new account starts with 0 credits and must
// purchase (supporters) or earn (creators) them.
const signupBonus = { Supporter: 0, Creator: 0, Admin: 0 };
const minimumWithdrawalCredits = 100;

app.use(cors({ 
  origin: clientUrl,
  credentials: true 
}));
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
    const reportsCollection = db.collection('reports');
    const creditPurchasesCollection = db.collection('creditPurchases');
    const notificationsCollection = db.collection('notifications');


    await Promise.all([
      usersCollection.createIndex({ email: 1 }, { unique: true }),
      creditPurchasesCollection.createIndex({ stripeSessionId: 1 }, { unique: true, sparse: true }),
      contributionsCollection.createIndex({ campaignId: 1, supporterEmail: 1 }),
    ]);

    // ==========================================
    // Middleware: Verify Token
    // ==========================================
    const verifyToken = async (req, res, next) => {

      // 1. Try Better Auth cookie via Next.js endpoint
      if (req.headers.cookie && req.headers.cookie.includes('crowdfundly.session_token')) {
        try {
          // Use global fetch (Node 18+)
          const response = await fetch(`${clientUrl}/api/auth/get-session`, {
            headers: { cookie: req.headers.cookie }
          });
          if (response.ok) {
            const sessionData = await response.json();
            if (sessionData && sessionData.user) {
              // Better-auth (e.g. Google) users live in better-auth's own `user`
              // collection. Mirror them into our app `users` collection so the
              // JWT-style endpoints (profile, credits, contributions, withdrawals,
              // stats) can find them by email. New mirrors start at 0 credits (no bonus).
              try {
                await usersCollection.updateOne(
                  { email: sessionData.user.email },
                  {
                    $setOnInsert: { credits: 0, createdAt: new Date() },
                    $set: {
                      name: sessionData.user.name || sessionData.user.email,
                      photoURL: sessionData.user.image || '',
                      role: sessionData.user.role || 'Supporter',
                    },
                  },
                  { upsert: true }
                );
              } catch (syncErr) {
                console.error('Failed to mirror better-auth user into users collection:', syncErr);
              }
              req.decoded = {
                email: sessionData.user.email,
                role: sessionData.user.role || 'Supporter',
                _id: sessionData.user.id
              };
              return next();
            }
          }
        } catch (e) {
          console.error("Better Auth token verification error:", e);
        }
      }

      // 2. Fallback to Legacy JWT
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
      const { name, email, password, photoURL } = req.body;
      const normalizedEmail = String(email || '').trim().toLowerCase();
      if (!String(name || '').trim() || !/^\S+@\S+\.\S+$/.test(normalizedEmail) || String(password || '').length < 8) {
        return res.status(400).send({ message: 'Name, a valid email, and an 8-character password are required' });
      }
      
      const query = { email: normalizedEmail };
      const existingUser = await usersCollection.findOne(query);
      if (existingUser) {
        return res.status(400).send({ message: 'User already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map((value) => value.trim().toLowerCase()).filter(Boolean);
      const role = adminEmails.includes(normalizedEmail) ? 'Admin' : (req.body.role === 'Creator' ? 'Creator' : 'Supporter');

      const newUser = {
        name,
        email: normalizedEmail,
        password: hashedPassword,
        role,
        photoURL: photoURL || '',
        credits: signupBonus[role] || 0,
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

    app.post('/api/auth/google', async (req, res) => {
      const { access_token, role } = req.body;
      if (!access_token) return res.status(400).send({ message: 'No token provided' });
      
      try {
        const response = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
          headers: { Authorization: `Bearer ${access_token}` }
        });
        const userInfo = await response.json();
        
        if (!userInfo.email) {
          return res.status(400).send({ message: 'Invalid Google token' });
        }
        
        const normalizedEmail = userInfo.email.toLowerCase();
        let user = await usersCollection.findOne({ email: normalizedEmail });
        
        if (!user) {
          // Register user
          const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map((v) => v.trim().toLowerCase()).filter(Boolean);
          const assignedRole = adminEmails.includes(normalizedEmail) ? 'Admin' : (role === 'Creator' ? 'Creator' : 'Supporter');
          
          user = {
            name: userInfo.name,
            email: normalizedEmail,
            photoURL: userInfo.picture || '',
            role: assignedRole,
            credits: signupBonus[assignedRole] || 0,
            createdAt: new Date(),
          };
          const result = await usersCollection.insertOne(user);
          user._id = result.insertedId;
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
      } catch (err) {
        res.status(500).send({ message: 'Google authentication failed' });
      }
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

    // Update User Profile
    app.patch('/api/users/profile', verifyToken, async (req, res) => {
      try {
        const email = req.decoded.email;
        const { name, photoURL } = req.body;
        
        const filter = { email: email };
        const updateDoc = {
          $set: {}
        };
        
        if (name !== undefined) updateDoc.$set.name = name;
        if (photoURL !== undefined) updateDoc.$set.photoURL = photoURL;
        
        if (Object.keys(updateDoc.$set).length === 0) {
          return res.status(400).send({ message: 'No fields to update' });
        }
        
        const result = await usersCollection.updateOne(filter, updateDoc);
        
        if (result.matchedCount > 0) {
          const updatedUser = await usersCollection.findOne(filter);
          res.send({ 
            message: 'Profile updated successfully',
            user: {
              _id: updatedUser._id,
              name: updatedUser.name,
              email: updatedUser.email,
              role: updatedUser.role,
              credits: updatedUser.credits,
              photoURL: updatedUser.photoURL
            }
          });
        } else {
          res.status(404).send({ message: 'User not found' });
        }
      } catch (error) {
        res.status(500).send({ message: 'Failed to update profile', error: error.message });
      }
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
        const { title, category, subCategory, location, shortDescription, story, targetAmount, duration, coverImage, team = [], rewards = [] } = req.body;
        const parsedTarget = Number(targetAmount);
        const parsedDuration = Number(duration);
        if (!String(title || '').trim() || !String(category || '').trim() || !Number.isFinite(parsedTarget) || parsedTarget <= 0 || !Number.isInteger(parsedDuration) || parsedDuration < 1 || parsedDuration > 365) {
          return res.status(400).send({ message: 'Provide a title, category, valid funding goal, and a duration from 1 to 365 days' });
        }
        const newCampaign = {
          title: String(title).trim(), category: String(category).trim(), subCategory: String(subCategory || '').trim(),
          location: String(location || '').trim(), shortDescription: String(shortDescription || '').trim(), story: String(story || '').trim(),
          targetAmount: parsedTarget, duration: parsedDuration, coverImage: String(coverImage || '').trim(),
          team: Array.isArray(team) ? team : [], rewards: Array.isArray(rewards) ? rewards : [],
          creatorEmail: req.decoded.email, creatorName: String(req.body.creatorName || '').trim(), creatorAvatar: String(req.body.creatorAvatar || '').trim(),
          createdAt: new Date(), status: 'Pending', raised: 0, backers: 0,
        };
        
        const result = await campaignsCollection.insertOne(newCampaign);
        res.status(201).send({ ...newCampaign, _id: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Failed to create campaign', error: error.message });
      }
    });

    // Public campaigns are always limited to approved records.
    app.get('/api/campaigns', async (req, res) => {
      try {
        const { search, category, sort } = req.query;
        let filter = { status: 'Approved' };
        
        if (search) {
          filter.$or = [
            { title: { $regex: search, $options: 'i' } },
            { shortDescription: { $regex: search, $options: 'i' } },
            { creatorName: { $regex: search, $options: 'i' } }
          ];
        }
        
        if (category && category !== 'All Projects') {
          filter.category = category;
        }

        let sortOption = { createdAt: -1 };
        if (sort === 'Funding Goal (High-Low)') {
          sortOption = { targetAmount: -1 };
        } else if (sort === 'Most Funded') {
          sortOption = { raised: -1 };
        }

        const campaigns = await campaignsCollection.find(filter).sort(sortOption).toArray();
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
        const campaign = await campaignsCollection.findOne({ ...query, status: 'Approved' });
        if (!campaign) return res.status(404).send({ message: 'Campaign not found' });
        res.send(campaign);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch campaign', error: error.message });
      }
    });

    // Public, database-backed platform metrics for the landing page.
    app.get('/api/platform/stats', async (req, res) => {
      try {
        const [campaigns, supporters, totals] = await Promise.all([
          campaignsCollection.countDocuments({ status: 'Approved' }),
          usersCollection.countDocuments({ role: 'Supporter' }),
          campaignsCollection.aggregate([
            { $match: { status: 'Approved' } },
            { $group: { _id: null, totalFunded: { $sum: '$raised' } } },
          ]).toArray(),
        ]);
        res.send({ totalFunded: totals[0]?.totalFunded || 0, activeCampaigns: campaigns, supporters });
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch platform stats' });
      }
    });

    // Update campaign (Edit)
    app.put('/api/campaigns/:id', verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const updateData = req.body;
        const filter = { _id: new ObjectId(id) };
        const campaign = await campaignsCollection.findOne(filter);
        
        if (!campaign) {
          return res.status(404).send({ message: 'Campaign not found' });
        }
        
        if (campaign.creatorEmail !== req.decoded.email) {
          return res.status(403).send({ message: 'Unauthorized: Only the creator can edit this campaign.' });
        }

        // Always revert status to Pending upon edit
        const updateDoc = {
          $set: {
            title: updateData.title || campaign.title,
            category: updateData.category || campaign.category,
            subCategory: updateData.subCategory || campaign.subCategory,
            location: updateData.location || campaign.location,
            shortDescription: updateData.shortDescription || campaign.shortDescription,
            story: updateData.story || campaign.story,
            targetAmount: Number(updateData.targetAmount) || campaign.targetAmount,
            duration: Number(updateData.duration) || campaign.duration,
            coverImage: updateData.coverImage || campaign.coverImage,
            teamName: updateData.teamName || campaign.teamName,
            teamRole: updateData.teamRole || campaign.teamRole,
            status: 'Pending',
            updatedAt: new Date()
          },
        };
        const result = await campaignsCollection.updateOne(filter, updateDoc);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to update campaign', error: error.message });
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

        // Notify Creator
        const campaign = await campaignsCollection.findOne(filter);
        if (campaign) {
          await notificationsCollection.insertOne({
            message: `Your campaign "${campaign.title}" was ${status.toLowerCase()} by Admin`,
            toEmail: campaign.creatorEmail,
            actionRoute: '/dashboard/my-campaigns',
            time: new Date(),
            read: false
          });
        }

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

        // Find all contributions for this campaign
        const contributions = await contributionsCollection.find({ campaignId: new ObjectId(id) }).toArray();
        
        for (let contrib of contributions) {
          if (contrib.status === 'Completed' || contrib.status === 'Pending') {
            // Refund the supporter
            await usersCollection.updateOne({ email: contrib.supporterEmail }, { $inc: { credits: contrib.amount } });
            
            // If it was completed, deduct from creator since they already got it
            if (contrib.status === 'Completed') {
              await usersCollection.updateOne({ email: campaign.creatorEmail }, { $inc: { credits: -contrib.amount } });
            }

            // Notify supporter
            await notificationsCollection.insertOne({
              message: `The campaign "${campaign.title}" was deleted. You have been refunded ${contrib.amount} credits.`,
              toEmail: contrib.supporterEmail,
              actionRoute: '/dashboard/contributions',
              time: new Date(),
              read: false
            });
          }
        }

        // Mark all contributions as Refunded
        await contributionsCollection.updateMany(
          { campaignId: new ObjectId(id) },
          { $set: { status: 'Refunded' } }
        );
        
        const result = await campaignsCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to delete campaign', error: error.message });
      }
    });

    // ==========================================
    // Dashboard Stats Route
    // ==========================================

    // Get dashboard stats for current user
    app.get('/api/dashboard/stats', verifyToken, async (req, res) => {
      try {
        const email = req.decoded.email;
        const role = req.decoded.role;

        if (role === 'Admin') {
          const [totalCampaigns, totalUsers, pendingCampaigns, totalWithdrawals] = await Promise.all([
            campaignsCollection.countDocuments({}),
            usersCollection.countDocuments({}),
            campaignsCollection.countDocuments({ status: 'Pending' }),
            withdrawalsCollection.countDocuments({ status: 'Pending' }),
          ]);
          return res.send({ totalCampaigns, totalUsers, pendingCampaigns, totalWithdrawals });
        }

        if (role === 'Creator') {
          const myCampaigns = await campaignsCollection.find({ creatorEmail: email }).toArray();
          const totalRaised = myCampaigns.reduce((sum, c) => sum + (c.raised || 0), 0);
          const approved = myCampaigns.filter(c => c.status === 'Approved').length;
          const pending = myCampaigns.filter(c => c.status === 'Pending').length;
          return res.send({ totalCampaigns: myCampaigns.length, totalRaised, approvedCampaigns: approved, pendingCampaigns: pending });
        }

        // Supporter
        const contributions = await contributionsCollection.find({ supporterEmail: email }).toArray();
        const totalContributed = contributions.reduce((sum, c) => sum + (c.amount || 0), 0);
        const uniqueCampaigns = new Set(contributions.map(c => c.campaignId?.toString())).size;
        const user = await usersCollection.findOne({ email }, { projection: { credits: 1 } });
        res.send({ totalContributions: contributions.length, totalContributed, projectsSupported: uniqueCampaigns, credits: user?.credits || 0 });
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch stats', error: error.message });
      }
    });

    // Get current user profile (credits etc)
    app.get('/api/users/me', verifyToken, async (req, res) => {
      try {
        const user = await usersCollection.findOne({ email: req.decoded.email }, { projection: { password: 0 } });
        if (!user) return res.status(404).send({ message: 'User not found' });
        res.send(user);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch user', error: error.message });
      }
    });

    // ==========================================
    // Credits & Contributions Routes
    // ==========================================

    // Credit purchase checkout. Credits are granted only after Stripe confirms payment.
    app.post('/api/credits/checkout-session', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Supporter') return res.status(403).send({ message: 'Only supporters can purchase contribution credits' });
        
        const credits = Number(req.body.credits);
        if (!Number.isInteger(credits) || credits < 100 || credits > 50000) {
          return res.status(400).send({ message: 'Choose between 100 and 50,000 credits' });
        }
        
        const user = await usersCollection.findOne({ email: req.decoded.email }, { projection: { _id: 1 } });
        if (!user) return res.status(404).send({ message: 'User not found' });
        
        if (!stripe || !process.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET_KEY === 'your_stripe_secret_key_here') {
          return res.status(503).send({ message: 'Stripe payments are not configured on this server.' });
        }

        const session = await stripe.checkout.sessions.create({
          mode: 'payment',
          client_reference_id: user._id.toString(),
          metadata: { userId: user._id.toString(), credits: String(credits) },
          line_items: [{ price_data: { currency: 'usd', product_data: { name: `${credits.toLocaleString()} Credits` }, unit_amount: Math.round((credits / creditsPerUsdPurchase) * 100) }, quantity: 1 }],
          success_url: `${clientUrl}/dashboard/credits?checkout=success&session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${clientUrl}/dashboard/credits?checkout=cancelled`,
        });
        res.send({ url: session.url });
      } catch (error) {
        res.status(500).send({ message: 'Unable to start secure checkout' });
      }
    });

    app.post('/api/credits/confirm-checkout', verifyToken, async (req, res) => {
      try {
        const sessionId = String(req.body.sessionId || '');
        if (!sessionId) return res.status(400).send({ message: 'Checkout session is required' });
        
        const user = await usersCollection.findOne({ email: req.decoded.email }, { projection: { _id: 1, credits: 1 } });
        if (!user) return res.status(404).send({ message: 'User not found' });
        
        let credits = 0;
        
        if (!stripe || !process.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET_KEY === 'your_stripe_secret_key_here') {
          return res.status(503).send({ message: 'Stripe payments are not configured on this server.' });
        }
        
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        credits = Number(session.metadata?.credits);
        
        if (session.payment_status !== 'paid' || session.client_reference_id !== user._id.toString() || !Number.isInteger(credits)) {
          return res.status(400).send({ message: 'Payment could not be verified' });
        }

        try {
          await creditPurchasesCollection.insertOne({ stripeSessionId: sessionId, userEmail: req.decoded.email, credits, amountUSD: credits / creditsPerUsdPurchase, createdAt: new Date() });
          await usersCollection.updateOne({ _id: user._id }, { $inc: { credits } });
          return res.send({ credits: (user.credits || 0) + credits, granted: credits });
        } catch (error) {
          if (error.code !== 11000) throw error;
          const currentUser = await usersCollection.findOne({ _id: user._id }, { projection: { credits: 1 } });
          return res.send({ credits: currentUser?.credits || 0, granted: 0, alreadyProcessed: true });
        }
      } catch (error) {
        console.error('Confirm checkout error:', error);
        res.status(500).send({ message: 'Unable to confirm credit purchase' });
      }
    });

    app.get('/api/credits/purchases', verifyToken, async (req, res) => {
      try {
        const purchases = await creditPurchasesCollection.find({ userEmail: req.decoded.email }).sort({ createdAt: -1 }).toArray();
        res.send(purchases);
      } catch (error) {
        res.status(500).send({ message: 'Unable to fetch payment history' });
      }
    });

    // Support an approved, active campaign using a supporter credit balance.
    app.post('/api/contributions', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Supporter') return res.status(403).send({ message: 'Only supporters can contribute' });
        const { campaignId, amount } = req.body;
        const parsedAmount = Number(amount);
        const userEmail = req.decoded.email;
        if (!ObjectId.isValid(campaignId) || !Number.isInteger(parsedAmount) || parsedAmount < 1) return res.status(400).send({ message: 'Enter a whole-number contribution of at least 1 credit' });
        const campaign = await campaignsCollection.findOne({ _id: new ObjectId(campaignId), status: 'Approved' });
        if (!campaign) return res.status(404).send({ message: 'Campaign is unavailable' });
        const deadline = new Date(new Date(campaign.createdAt).getTime() + campaign.duration * 86400000);
        if (deadline <= new Date()) return res.status(400).send({ message: 'This campaign has ended' });
        const debit = await usersCollection.updateOne({ email: userEmail, credits: { $gte: parsedAmount } }, { $inc: { credits: -parsedAmount } });
        if (!debit.matchedCount) return res.status(400).send({ message: 'Insufficient credit balance' });
        // DO NOT add to campaign or creator yet (escrowed)
        // Record contribution
        const newContribution = {
          campaignId: campaign._id,
          campaignTitle: campaign.title,
          creatorEmail: campaign.creatorEmail,
          creatorName: campaign.creatorName,
          supporterEmail: userEmail,
          amount: parsedAmount,
          amountUSD: parsedAmount / creditsPerUsdPurchase,
          paymentMethod: 'Credits',
          date: new Date(),
          status: 'Pending',
          receiptNumber: `CF-${Date.now()}`,
        };
        const result = await contributionsCollection.insertOne(newContribution);
        
        // Notify Creator
        await notificationsCollection.insertOne({
          message: `You received a new pending contribution of ${parsedAmount} credits for "${campaign.title}"`,
          toEmail: campaign.creatorEmail,
          actionRoute: '/dashboard/review-contributions',
          time: new Date(),
          read: false
        });

        res.status(201).send({ ...newContribution, _id: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Failed to process contribution', error: error.message });
      }
    });

    // Get creator's pending contributions to review
    app.get('/api/contributions/review', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Creator') return res.status(403).send({ message: 'Only creators can review contributions' });
        const pendingContributions = await contributionsCollection.find({ 
          creatorEmail: req.decoded.email, 
          status: 'Pending' 
        }).sort({ date: -1 }).toArray();
        res.send(pendingContributions);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch contributions', error: error.message });
      }
    });

    // Update contribution status (Approve / Reject)
    app.patch('/api/contributions/:id/status', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Creator') return res.status(403).send({ message: 'Only creators can update contribution status' });
        
        const id = req.params.id;
        const { status } = req.body; // 'Completed' (Approved) or 'Rejected'
        if (!['Completed', 'Rejected'].includes(status)) {
          return res.status(400).send({ message: 'Invalid status' });
        }

        const filter = { _id: new ObjectId(id), creatorEmail: req.decoded.email, status: 'Pending' };
        const contribution = await contributionsCollection.findOne(filter);
        if (!contribution) return res.status(404).send({ message: 'Pending contribution not found' });

        if (status === 'Completed') {
          // Add funds to campaign and creator
          await campaignsCollection.updateOne({ _id: contribution.campaignId }, { $inc: { raised: contribution.amount, backers: 1 } });
          await usersCollection.updateOne({ email: contribution.creatorEmail }, { $inc: { credits: contribution.amount } });
        } else if (status === 'Rejected') {
          // Refund to supporter
          await usersCollection.updateOne({ email: contribution.supporterEmail }, { $inc: { credits: contribution.amount } });
        }

        await contributionsCollection.updateOne(filter, { $set: { status } });

        // Notify Supporter
        await notificationsCollection.insertOne({
          message: `Your contribution of ${contribution.amount} credits to "${contribution.campaignTitle}" was ${status === 'Completed' ? 'approved' : 'rejected'} by the creator.`,
          toEmail: contribution.supporterEmail,
          actionRoute: '/dashboard/contributions',
          time: new Date(),
          read: false
        });

        res.send({ message: `Contribution ${status}` });
      } catch (error) {
        res.status(500).send({ message: 'Failed to update status', error: error.message });
      }
    });

    // Get user contributions
    app.get('/api/contributions', verifyToken, async (req, res) => {
      try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;
        
        const query = { supporterEmail: req.decoded.email };
        const total = await contributionsCollection.countDocuments(query);
        
        const contributions = await contributionsCollection
          .find(query)
          .sort({ date: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();
          
        res.send({
          contributions,
          currentPage: page,
          totalPages: Math.ceil(total / limit),
          totalItems: total
        });
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
        const parsedCredits = Number(creditsToWithdraw);
        const userEmail = req.decoded.email;

        if (!Number.isInteger(parsedCredits) || parsedCredits < minimumWithdrawalCredits || !['bank', 'paypal', 'stripe'].includes(paymentMethod) || !String(paymentDetails || '').trim()) {
          return res.status(400).send({ message: `Enter at least ${minimumWithdrawalCredits} credits and valid payment details` });
        }

        // Check user balance
        const user = await usersCollection.findOne({ email: userEmail });
        if (!user || user.credits < parsedCredits) {
          return res.status(400).send({ message: 'Insufficient credits for withdrawal' });
        }

        // Deduct credits immediately (escrow) atomically preventing negative balance
        const debit = await usersCollection.updateOne(
          { email: userEmail, credits: { $gte: parsedCredits } },
          { $inc: { credits: -parsedCredits } }
        );

        if (!debit.matchedCount) {
          return res.status(400).send({ message: 'Insufficient credits for withdrawal' });
        }

        const newWithdrawal = {
          creatorEmail: userEmail,
          credits: parsedCredits,
          amountUSD: parsedCredits / creditsPerUsdWithdraw,
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
        const { status } = req.body;
        if (!['Processed', 'Denied'].includes(status)) return res.status(400).send({ message: 'Invalid withdrawal status' });
        
        const filter = { _id: new ObjectId(id) };
        const withdrawal = await withdrawalsCollection.findOne({ ...filter, status: 'Pending' });
        if (!withdrawal) return res.status(404).send({ message: 'Pending withdrawal not found' });
        const result = await withdrawalsCollection.updateOne({ ...filter, status: 'Pending' }, { $set: { status, processedDate: new Date() } });
        
        // If denied, refund the credits to creator
        if (status === 'Denied') {
           await usersCollection.updateOne({ email: withdrawal.creatorEmail }, { $inc: { credits: withdrawal.credits } });
        }
        
        // Notify Creator
        await notificationsCollection.insertOne({
          message: `Your withdrawal request for $${(withdrawal.credits / creditsPerUsdWithdraw).toFixed(2)} USD was ${status.toLowerCase()} by Admin`,
          toEmail: withdrawal.creatorEmail,
          actionRoute: '/dashboard/history',
          time: new Date(),
          read: false
        });

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to update withdrawal', error: error.message });
      }
    });

    // ==========================================
    // Admin Routes
    // ==========================================

    // Get all users
    app.get('/api/admin/campaigns', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Admin') return res.status(403).send({ message: 'Admin access required' });
        const campaigns = await campaignsCollection.find({}).sort({ createdAt: -1 }).toArray();
        res.send(campaigns);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch campaigns' });
      }
    });

    app.get('/api/creator/campaigns', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Creator') return res.status(403).send({ message: 'Creator access required' });
        const campaigns = await campaignsCollection.find({ creatorEmail: req.decoded.email }).sort({ createdAt: -1 }).toArray();
        res.send(campaigns);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch campaigns' });
      }
    });

    app.get('/api/creator/campaigns/:id', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Creator') return res.status(403).send({ message: 'Creator access required' });
        const id = req.params.id;
        const filter = { _id: new ObjectId(id), creatorEmail: req.decoded.email };
        const campaign = await campaignsCollection.findOne(filter);
        if (!campaign) {
          return res.status(404).send({ message: 'Campaign not found' });
        }
        res.send(campaign);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch campaign' });
      }
    });

    app.get('/api/admin/users', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Admin') return res.status(403).send({ message: 'Admin access required' });
        const users = await usersCollection.find({}, { projection: { password: 0 } }).toArray();
        res.send(users);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch users', error: error.message });
      }
    });

    // Update user role (Admin)
    app.patch('/api/admin/users/:id/role', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Admin') return res.status(403).send({ message: 'Admin access required' });
        const { role } = req.body;
        if (!['Supporter', 'Creator', 'Admin'].includes(role)) return res.status(400).send({ message: 'Invalid role' });
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { role } }
        );
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to update role', error: error.message });
      }
    });

    // Delete user (Admin)
    app.delete('/api/admin/users/:id', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Admin') return res.status(403).send({ message: 'Admin access required' });
        const result = await usersCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to delete user', error: error.message });
      }
    });

    app.get('/', (req, res) => {
      res.send('Crowdfundly Server is running!');
    });

    // ==========================================
    // Reports Routes
    // ==========================================

    // Get all reports (Admin)
    app.get('/api/reports', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Admin') return res.status(403).send({ message: 'Admin access required' });
        const reports = await reportsCollection.find({}).sort({ createdAt: -1 }).toArray();
        res.send(reports);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch reports', error: error.message });
      }
    });

    // Submit a report (any logged-in user)
    app.post('/api/reports', verifyToken, async (req, res) => {
      try {
        const { campaignId, campaignTitle, reason, description } = req.body;
        const newReport = {
          campaignId: campaignId ? new ObjectId(campaignId) : null,
          campaignTitle,
          reason,
          description: description || '',
          reporterEmail: req.decoded.email,
          status: 'Pending',
          createdAt: new Date(),
        };
        const result = await reportsCollection.insertOne(newReport);
        res.status(201).send({ ...newReport, _id: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Failed to submit report', error: error.message });
      }
    });

    // Update report status (Admin: Reviewed / Dismissed)
    app.patch('/api/reports/:id/status', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Admin') return res.status(403).send({ message: 'Admin access required' });
        const { status } = req.body;
        const result = await reportsCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { status, reviewedAt: new Date() } }
        );
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to update report', error: error.message });
      }
    });

    // Delete a report (Admin)
    app.delete('/api/reports/:id', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Admin') return res.status(403).send({ message: 'Admin access required' });
        const result = await reportsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to delete report', error: error.message });
      }
    });

    // Admin platform stats — also add report count
    // (already done, no change needed)

    // ==========================================
    // Notifications Routes
    // ==========================================
    app.post('/api/notifications', verifyToken, async (req, res) => {
      try {
        if (req.decoded.role !== 'Admin') {
          return res.status(403).send({ message: 'Only admins can send manual notifications' });
        }
        const { message, toEmail } = req.body;
        if (!message) return res.status(400).send({ message: 'Message is required' });
        
        const newNotif = {
          message,
          toEmail: toEmail || 'all', // 'all' means broadcast
          actionRoute: '/dashboard',
          time: new Date(),
          read: false,
          isManual: true
        };
        const result = await notificationsCollection.insertOne(newNotif);
        res.status(201).send({ ...newNotif, _id: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Failed to send notification', error: error.message });
      }
    });

    app.get('/api/notifications', verifyToken, async (req, res) => {
      try {
        const notifications = await notificationsCollection
          .find({ $or: [{ toEmail: req.decoded.email }, { toEmail: 'all' }] })
          .sort({ time: -1 })
          .toArray();
        res.send(notifications);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch notifications', error: error.message });
      }
    });

    app.patch('/api/notifications/mark-read', verifyToken, async (req, res) => {
      try {
        const result = await notificationsCollection.updateMany(
          { $or: [{ toEmail: req.decoded.email }, { toEmail: 'all' }], read: { $ne: true } },
          { $set: { read: true } }
        );
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to mark as read', error: error.message });
      }
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");

    // Start listening if not in Vercel serverless environment
    if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
      app.listen(port, () => {
        console.log(`Server is running on port ${port}`);
      });
    }
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

// Export for Vercel Serverless
module.exports = app;
