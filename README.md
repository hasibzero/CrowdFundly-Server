# Crowdfundly Server (Backend) 🚀

Crowdfundly is a full-stack crowdfunding platform built to empower creators to launch their ideas and supporters to back innovative projects. Built with Next.js, Express, and MongoDB, Crowdfundly provides a secure, reliable, and user-friendly experience featuring role-based access, automated payments, and comprehensive admin tools.

This repository contains the **Express Backend API** for Crowdfundly.

## 🔗 Live Demo & Links
- **Client Deployment**: [https://crowdfundly-client.vercel.app/](https://crowdfundly-client.vercel.app/)
- **Server Deployment**: [https://crowdfundly-server.vercel.app/](https://crowdfundly-server.vercel.app/)

## 🔑 Admin Test Credentials
To access the admin dashboard, use the following credentials:
- **Email**: admin@crowdfundly.com
- **Password**: admin123

> The admin account must be registered and the email must be listed in the server's `ADMIN_EMAILS` allowlist so the Admin role is applied.

## ✨ Key Features (10+)

1. **Role-Based Authentication (RBAC):** Secure JWT-based login with distinct dashboards for Supporters, Creators, and Admins. Includes Google Sign-In integration.
2. **Dynamic Campaign Management:** Creators can seamlessly add, edit, and delete campaigns. Built-in integration with ImgBB allows effortless image uploads.
3. **Admin Approval Workflow:** New and edited campaigns automatically enter a pending state, requiring Admin review to ensure platform safety and quality.
4. **Automated Notification System:** A global, real-time-like notification system alerts users of status changes (e.g., campaign approvals, successful contributions, and withdrawal updates).
5. **Credit Purchasing & Stripe Integration:** Supporters can securely purchase platform credits through Stripe across 4 tier packages to back campaigns.
6. **Contribution Processing & Refunds:** Creators can review incoming contributions. Approvals add to the campaign's total, while rejections automatically refund the Supporter's credits.
7. **Withdrawal System with Automated Math:** Creators can request fund withdrawals once they exceed the minimum threshold, converting credits to USD.
8. **Suspicious Activity Reporting:** Supporters can flag potentially fraudulent campaigns, sending detailed reports directly to the Admin dashboard for investigation.
9. **Responsive & Premium Design:** The platform is fully responsive and features dynamic hero sliders, testimonials, and clean modern aesthetics utilizing Framer Motion for smooth transitions.
10. **Admin Master Controls:** Administrators have full oversight to manage all registered users, handle withdrawal requests, review flagged campaigns, and oversee the entire platform ecosystem.
11. **Client-Side Pagination:** Optimized rendering and pagination built directly into campaign lists, contribution tables, and admin user directories for smooth performance at scale.

## 🛠️ Technology Stack
- **Frontend**: React, Next.js (App Router), TailwindCSS, Framer Motion, Axios
- **Backend**: Node.js, Express.js, MongoDB (Native Driver), JWT (JSON Web Tokens)
- **Third-Party Integrations**: Stripe (Payments), ImgBB (Image Hosting)

## 🚀 Backend Local Setup

### Prerequisites
- Node.js 18+ installed
- A MongoDB connection string (MongoDB Atlas or local)

### Setup Instructions
1. Navigate to the server directory (if not already there): `cd server`
2. Install dependencies: `npm install`
3. Create a `.env` file. Required variables:
   - `PORT` — API port (e.g. `5000`)
   - `MONGODB_URI` — MongoDB connection string
   - `ACCESS_TOKEN_SECRET` — long random string used to sign JWTs
   - `CLIENT_URL` — the client's origin, used for CORS and Better Auth session checks (e.g. `http://localhost:3000`)
   - `ADMIN_EMAILS` — comma-separated allowlist of emails that receive the Admin role (e.g. `admin@crowdfundly.com`)
   - `STRIPE_SECRET_KEY` — Stripe secret key (for credit purchases)
4. Start the server: `npm start` (or `npm run dev`)

## ☁️ Deployment

### Server (Render, Railway, Vercel, or similar)
- Build command: `npm install`
- Start command: `npm start`
- Set every variable from your local `.env` in the host's dashboard.
- Set `CLIENT_URL` to your deployed client URL (this drives CORS and Better Auth session verification — a wrong value will break authenticated requests).