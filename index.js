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
const creditsPerUsd = 10;
const minimumWithdrawalCredits = 100;

app.use(cors({ origin: clientUrl }));
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

    await Promise.all([
      usersCollection.createIndex({ email: 1 }, { unique: true }),
      creditPurchasesCollection.createIndex({ stripeSessionId: 1 }, { unique: true, sparse: true }),
      contributionsCollection.createIndex({ campaignId: 1, supporterEmail: 1 }),
    ]);

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
        credits: role === 'Supporter' ? 50 : role === 'Creator' ? 20 : 0,
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
        const campaigns = await campaignsCollection.find({ status: 'Approved' }).sort({ createdAt: -1 }).toArray();
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
        if (!stripe) return res.status(503).send({ message: 'Credit purchases are not configured yet' });
        const credits = Number(req.body.credits);
        if (!Number.isInteger(credits) || credits < 100 || credits > 50000) {
          return res.status(400).send({ message: 'Choose between 100 and 50,000 credits' });
        }
        const user = await usersCollection.findOne({ email: req.decoded.email }, { projection: { _id: 1 } });
        if (!user) return res.status(404).send({ message: 'User not found' });
        const session = await stripe.checkout.sessions.create({
          mode: 'payment',
          client_reference_id: user._id.toString(),
          metadata: { userId: user._id.toString(), credits: String(credits) },
          line_items: [{ price_data: { currency: 'usd', product_data: { name: `${credits.toLocaleString()} Crowdfundly credits` }, unit_amount: Math.round((credits / creditsPerUsd) * 100) }, quantity: 1 }],
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
        if (!stripe) return res.status(503).send({ message: 'Credit purchases are not configured yet' });
        const sessionId = String(req.body.sessionId || '');
        if (!sessionId) return res.status(400).send({ message: 'Checkout session is required' });
        const user = await usersCollection.findOne({ email: req.decoded.email }, { projection: { _id: 1, credits: 1 } });
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        const credits = Number(session.metadata?.credits);
        if (!user || session.payment_status !== 'paid' || session.client_reference_id !== user._id.toString() || !Number.isInteger(credits)) {
          return res.status(400).send({ message: 'Payment could not be verified' });
        }
        try {
          await creditPurchasesCollection.insertOne({ stripeSessionId: session.id, userEmail: req.decoded.email, credits, amountUSD: credits / creditsPerUsd, createdAt: new Date() });
          await usersCollection.updateOne({ _id: user._id }, { $inc: { credits } });
          return res.send({ credits: (user.credits || 0) + credits, granted: credits });
        } catch (error) {
          if (error.code !== 11000) throw error;
          const currentUser = await usersCollection.findOne({ _id: user._id }, { projection: { credits: 1 } });
          return res.send({ credits: currentUser?.credits || 0, granted: 0, alreadyProcessed: true });
        }
      } catch (error) {
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
        if (!debit.matchedCount) return res.status(400).send({ message: 'Insufficient credits' });
        const existingContribution = await contributionsCollection.findOne({ campaignId: campaign._id, supporterEmail: userEmail });
        await campaignsCollection.updateOne({ _id: campaign._id }, { $inc: { raised: parsedAmount, backers: existingContribution ? 0 : 1 } });
        await usersCollection.updateOne({ email: campaign.creatorEmail, role: 'Creator' }, { $inc: { credits: parsedAmount } });

        // Record contribution
        const newContribution = {
          campaignId: campaign._id,
          supporterEmail: userEmail,
          amount: parsedAmount,
          amountUSD: parsedAmount / creditsPerUsd,
          paymentMethod: 'Credits',
          date: new Date(),
          status: 'Completed',
          receiptNumber: `CF-${Date.now()}`,
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

        // Deduct credits immediately (escrow)
        await usersCollection.updateOne(
          { email: userEmail },
          { $inc: { credits: -parsedCredits } }
        );

        const newWithdrawal = {
          creatorEmail: userEmail,
          credits: parsedCredits,
          amountUSD: parsedCredits / creditsPerUsd,
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

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");

    app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);
