# Cloud Deployment Guide — Free Live Website Link

Follow this step-by-step guide to deploy your **Secure File Sharing** application to the cloud for 100% free. This will give you a permanent live web link (e.g. `https://securefilesharing.vercel.app`) that anyone in the world can open on their phone or computer!

---

## Architecture Overview

- **Frontend UI (React + Vite):** Deployed to **Vercel** (Free live CDN hosting).
- **Backend API (Flask + Cryptography + SQLite):** Deployed to **Render** (Free Web Service hosting).

---

## Step 1: Push Code to GitHub (2 Minutes)

1. Log in to [GitHub.com](https://github.com) (or create a free account).
2. Click **+** (top right) -> **New repository**.
3. Repository name: `securefilesharing` -> Click **Create repository**.
4. Open PowerShell in your project folder (`c:\Users\bojja_raj9umt\OneDrive\Desktop\securefilesharing`) and run:

```powershell
git init
git add .
git commit -m "Deploying to Vercel and Render"
git branch -M main
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/securefilesharing.git
git push -u origin main
```

---

## Step 2: Deploy Backend API to Render.com (Free)

1. Log in to [Render.com](https://render.com) using your GitHub account.
2. Click **New +** -> **Web Service**.
3. Select your `securefilesharing` GitHub repository.
4. Fill in the deployment details:
   - **Name:** `securefilesharing-api`
   - **Root Directory:** `backend`
   - **Environment:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn run:app`
5. Click **Create Web Service**.
6. Render will build your backend and provide a live API URL:
   `https://securefilesharing-api.onrender.com`

---

## Step 3: Deploy Frontend to Vercel (Free & Instant)

1. Log in to [Vercel.com](https://vercel.com) using your GitHub account.
2. Click **Add New...** -> **Project**.
3. Import your `securefilesharing` GitHub repository.
4. Configure Project Settings:
   - **Framework Preset:** `Vite`
   - **Root Directory:** Click Edit and select `frontend`.
5. Under **Environment Variables**, add:
   - **Key:** `VITE_API_URL`
   - **Value:** `https://securefilesharing-api.onrender.com` (Replace with your Render backend URL from Step 2)
6. Click **Deploy**!

---

## Live Website Ready! 🎉

Vercel will generate your **Permanent Live Website URL** (e.g. `https://securefilesharing.vercel.app`).

You can send this single web link to anyone in the world. Anyone clicking the link can register, log in, upload encrypted files, share via ECC P-256 / ECDH, and download decrypted payloads directly in their browser!
