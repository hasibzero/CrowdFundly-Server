const { betterAuth } = require("better-auth");
const { mongodbAdapter } = require("better-auth/adapters/mongodb");
const { jwt } = require("better-auth/plugins");

const createAuth = (db, client) => {
  return betterAuth({
    database: mongodbAdapter(db, {
      client, // Reusing existing MongoClient for transactions
    }),
    emailAndPassword: {
      enabled: true,
      autoSignIn: true,
    },
    plugins: [
      jwt({
        jwt: {
          expirationTime: '7d',
        }
      })
    ],
    secret: process.env.ACCESS_TOKEN_SECRET || "fallback_secret",
    baseURL: process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000",
  });
};

module.exports = { createAuth };
