require('dotenv').config();
const { MongoClient, ServerApiVersion } = require('mongodb');

const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

const sampleCampaign = {
  title: "AeroGrow: AI-Driven Urban Farm",
  category: "Technology",
  subCategory: "Hardware",
  location: "Seattle, WA",
  coverImage: "https://images.unsplash.com/photo-1530836369250-ef71a3f5e48d?auto=format&fit=crop&q=80&w=1200",
  shortDescription: "Bring the future of sustainable agriculture into your home with our intelligent, fully-automated hydroponic system.",
  story: "We believe that everyone deserves access to fresh, pesticide-free produce, regardless of where they live. AeroGrow was born out of a desire to democratize urban farming, making it accessible, efficient, and beautiful.\n\nBy combining advanced hydroponics with machine learning, AeroGrow takes the guesswork out of gardening. Our AI monitors nutrient levels, pH, and lighting, adjusting in real-time to ensure optimal growth for a variety of crops.\n\nTraditional agriculture consumes massive amounts of water and relies heavily on transportation. AeroGrow uses 95% less water than soil-based farming and completely eliminates food miles. You are quite literally eating what you grow, just steps from your kitchen.\n\nBy backing AeroGrow, you aren't just buying a product; you're investing in a more sustainable future for urban living. Join us in bringing the farm to the living room.",
  targetAmount: 50000,
  raised: 42500,
  backers: 342,
  duration: 30,
  status: "Approved",
  creatorEmail: "elena@example.com",
  creatorName: "Elena Rostova",
  createdAt: new Date(Date.now() - 16 * 24 * 60 * 60 * 1000), // 16 days ago
  team: [
    { name: "Sarah Jenkins", role: "CEO & Lead Engineer", initials: "SJ" },
    { name: "Marcus Reed", role: "Head of Botany", initials: "MR" }
  ],
  rewards: [
    {
      title: "Supporter",
      amount: 25,
      description: "Show your support for sustainable agriculture! Get exclusive behind-the-scenes updates and your name on our virtual backer wall.",
      items: ["Exclusive Updates", "Digital Backer Wall"],
      estimatedDelivery: "Aug 2024",
      backers: 124
    },
    {
      title: "Early Bird AeroGrow",
      amount: 249,
      description: "Get the complete AeroGrow system at a significant discount off retail price. Everything you need to start growing immediately.",
      items: ["1x AeroGrow Smart Farm", "Starter Seed Pod Kit (12 pods)", "Nutrient Solution (6 month supply)", "App Access"],
      estimatedDelivery: "Nov 2024",
      backers: 185,
      popular: true
    }
  ]
};

async function seed() {
  try {
    await client.connect();
    const db = client.db('crowdfundly');
    const campaignsCollection = db.collection('campaigns');

    // Check if it already exists
    const existing = await campaignsCollection.findOne({ title: "AeroGrow: AI-Driven Urban Farm" });
    if (!existing) {
      const result = await campaignsCollection.insertOne(sampleCampaign);
      console.log("Successfully inserted sample campaign with ID:", result.insertedId);
    } else {
      console.log("Sample campaign already exists.");
    }
  } catch (err) {
    console.error("Error seeding DB:", err);
  } finally {
    await client.close();
  }
}

seed();
