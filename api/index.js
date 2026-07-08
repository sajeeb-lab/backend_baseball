const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const axios    = require('axios');
const mongoose = require('mongoose');
const FormData = require('form-data');
const crypto   = require('crypto');
const nodemailer = require('nodemailer');
const Stripe   = require('stripe');

// ── STRIPE INIT ───────────────────────────────────────────────
const stripe = process.env.STRIPE_SECRET_KEY
  ? Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

// ── EMAIL TRANSPORTER ─────────────────────────────────────────
function createTransporter() {
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
}

async function sendOTPEmail(toEmail, otp, purpose) {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.warn('⚠️  EMAIL_USER / EMAIL_PASS not set — skipping email send. OTP:', otp);
    return;
  }
  const subject = purpose === 'reset'
    ? 'Ambassadors Baseball – Password Reset Code'
    : 'Ambassadors Baseball – Verify Your Identity';
  const html = `
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;border:1px solid #dce3ec;border-radius:8px">
      <div style="background:#0a1628;padding:16px 20px;border-radius:6px 6px 0 0;margin:-24px -24px 24px">
        <h2 style="color:#fff;margin:0;font-size:1.1rem;letter-spacing:.05em;text-transform:uppercase">Ambassadors Baseball</h2>
      </div>
      <p style="color:#1a1a2e;font-size:.95rem;margin-bottom:8px">
        ${purpose === 'reset'
          ? 'You requested a password reset. Use the code below to set a new password:'
          : 'Use the code below to verify your identity and change your password:'}
      </p>
      <div style="text-align:center;margin:24px 0">
        <span style="display:inline-block;background:#f4f6f9;border:2px dashed #c8102e;border-radius:8px;padding:14px 32px;font-size:2rem;font-weight:700;letter-spacing:.35em;color:#0a1628;font-family:monospace">${otp}</span>
      </div>
      <p style="color:#5a6a7a;font-size:.82rem;margin:0">This code expires in <strong>10 minutes</strong>. If you didn't request this, you can safely ignore this email.</p>
    </div>`;
  await createTransporter().sendMail({
    from: `"Ambassadors Baseball" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject,
    html,
  });
}

function generateOTP() {
  return String(Math.floor(100000 + crypto.randomInt(900000))).padStart(6, '0');
}

// ── PAYMENT NOTIFICATION EMAIL ────────────────────────────────
// Used for the staff-facing notifications (Coach / Jahirul / Sajeeb).
// `subject` and `recipients` are passed in so the same body can be sent
// with different subjects to different audiences (coach gets one subject,
// internal staff gets a different one).
async function sendPaymentNotificationEmail({ subject, recipients, playerName, paymentType, amountPaid, totalFee, balance, status, playerEmail, playerCell, coachName, teamName }) {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.warn('⚠️  EMAIL_USER / EMAIL_PASS not set — skipping payment notification email');
    return;
  }
  if (!recipients) {
    console.warn('⚠️  No recipients for payment notification — skipping');
    return;
  }
  const fmt = n => '$' + (parseFloat(n) || 0).toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const typeLabel = { full: 'Full Payment', deposit: 'Deposit', remainder: 'Remaining Balance', installment: 'Installment' }[paymentType] || paymentType;
  const html = `
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:24px;border:1px solid #dce3ec;border-radius:8px">
      <div style="background:#0a1628;padding:16px 20px;border-radius:6px 6px 0 0;margin:-24px -24px 24px">
        <h2 style="color:#fff;margin:0;font-size:1.1rem;letter-spacing:.05em;text-transform:uppercase">Ambassadors Baseball — Payment Received</h2>
      </div>
      <p style="color:#1a1a2e;font-size:.95rem;margin-bottom:20px">A payment has been successfully processed.</p>
      <table style="width:100%;border-collapse:collapse;font-size:.9rem;margin-bottom:20px">
        <tr style="background:#f4f6f9"><td style="padding:9px 12px;color:#5a6a7a;width:40%">Player Name</td><td style="padding:9px 12px;color:#0a1628;font-weight:700">${playerName || '—'}</td></tr>
        <tr><td style="padding:9px 12px;color:#5a6a7a">Team</td><td style="padding:9px 12px;color:#0a1628">${teamName || '—'}</td></tr>
        <tr style="background:#f4f6f9"><td style="padding:9px 12px;color:#5a6a7a">Coach Name</td><td style="padding:9px 12px;color:#0a1628">${coachName || '—'}</td></tr>
        <tr><td style="padding:9px 12px;color:#5a6a7a">Player Email</td><td style="padding:9px 12px;color:#0a1628">${playerEmail || '—'}</td></tr>
        <tr style="background:#f4f6f9"><td style="padding:9px 12px;color:#5a6a7a">Player Cell</td><td style="padding:9px 12px;color:#0a1628">${playerCell || '—'}</td></tr>
        <tr><td style="padding:9px 12px;color:#5a6a7a">Payment Type</td><td style="padding:9px 12px;color:#0a1628">${typeLabel}</td></tr>
        <tr style="background:#f4f6f9"><td style="padding:9px 12px;color:#5a6a7a">Amount Paid</td><td style="padding:9px 12px;color:#2d7a2d;font-weight:700">${fmt(amountPaid)}</td></tr>
        <tr><td style="padding:9px 12px;color:#5a6a7a">Total Fee</td><td style="padding:9px 12px;color:#0a1628">${fmt(totalFee)}</td></tr>
        <tr style="background:#f4f6f9"><td style="padding:9px 12px;color:#5a6a7a">Remaining Balance</td><td style="padding:9px 12px;color:${parseFloat(balance) > 0 ? '#c8102e' : '#2d7a2d'};font-weight:700">${fmt(balance)}</td></tr>
        <tr><td style="padding:9px 12px;color:#5a6a7a">Status</td><td style="padding:9px 12px;color:#0a1628;font-weight:700">${status || '—'}</td></tr>
      </table>
      <p style="color:#5a6a7a;font-size:.8rem;margin:0">This is an automated notification from Ambassadors Baseball.</p>
    </div>`;
  try {
    await createTransporter().sendMail({
      from: `"Ambassadors Baseball" <${process.env.EMAIL_USER}>`,
      to: recipients,
      subject,
      html,
    });
    console.log(`📧  Payment notification email sent — to=${recipients} subject="${subject}"`);
  } catch (err) {
    console.error('⚠️  Failed to send payment notification email:', err.message);
  }
}

// ── PLAYER WELCOME EMAIL ──────────────────────────────────────
// Sent to the player on every successful payment that triggers the notification flow.
// Subject: "Welcome to Ambassadors Baseball"
async function sendPlayerWelcomeEmail({ playerEmail, playerName }) {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.warn('⚠️  EMAIL_USER / EMAIL_PASS not set — skipping player welcome email');
    return;
  }
  if (!playerEmail) {
    console.log('ℹ️  No player email on file — skipping player welcome email');
    return;
  }
  // First name: take the first whitespace-delimited token of the full name.
  const firstName = (playerName || '').trim().split(/\s+/)[0] || 'Player';

  // Plain-text body (preserves the exact wording supplied).
  const text =
`Hello ${firstName},

Welcome to Ambassadors Baseball!

Congratulations on becoming part of a program built on faith, hard work, accountability, development, and excellence. We are excited to have you with us and can't wait to begin this journey together.

This is a big opportunity.

If you fully commit yourself to the process — as a player, teammate, leader, and young man — this experience can truly become a major stepping stone in both your baseball career and your life.

At Ambassadors Baseball, we believe God has a purpose and plan for every player. Our job is to trust Him, work hard, stay grateful, and give our best effort every single day.

Now that you are officially registered, there are a couple important "next step" items you need to complete as soon as possible:

1. Join The HUB
The HUB is where players receive important updates, communication, schedules, training information, and announcements.
https://portal.theambassadorsgroup.com

2. Complete Your VTS (Video Training Series)
The VTS will introduce you to the Ambassadors culture, standards, expectations, and mindset.
This is an important part of becoming an Ambassadors player and should be completed promptly.
You will find the Training Course in the Hub when you set up your new account.

Most importantly, take pride in being part of Ambassadors Baseball. Represent your family, your teammates, and your faith the right way both on and off the field.

Be coachable. Be accountable. Be grateful. Compete hard. Trust God's plan.

We're excited to get started.

Welcome to the family!

Mark Helsel
"Coach Mark"
Founder, Ambassadors Baseball`;

  // HTML version — same content, light formatting.
  // A per-send invisible token prevents Gmail from collapsing similar messages
  // ("…" trim quoted content). Zero visual impact; only affects email-client dedup.
  const _uniq = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
  const html = `
    <div style="background:#ffffff;padding:0;margin:0;">
      <div style="display:none;max-height:0;overflow:hidden;mso-hide:all;font-size:0;line-height:0;color:transparent;opacity:0;visibility:hidden;">${_uniq}</div>
      <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;max-width:620px;margin:0 auto;background:#ffffff;color:#1a1a2e;line-height:1.7;font-size:15px;">

        <!-- Banner -->
        <div style="background:#0a1628;padding:28px 32px;text-align:center;border-bottom:3px solid #c8102e;">
          <h1 style="color:#ffffff;margin:0;font-size:18px;letter-spacing:0.18em;text-transform:uppercase;font-weight:700;">Ambassadors Baseball</h1>
          <p style="color:#a8b5c4;margin:8px 0 0;font-size:11px;letter-spacing:0.2em;text-transform:uppercase;">Welcome to the Family</p>
        </div>

        <!-- Body -->
        <div style="padding:36px 32px;background:#ffffff;">
          <p style="margin:0 0 18px;">Hello <strong>${firstName}</strong>,</p>
          <p style="margin:0 0 18px;font-size:17px;color:#0a1628;"><strong>Welcome to Ambassadors Baseball!</strong></p>
          <p style="margin:0 0 18px;">Congratulations on becoming part of a program built on faith, hard work, accountability, development, and excellence. We are excited to have you with us and can't wait to begin this journey together.</p>
          <p style="margin:0 0 18px;font-weight:700;color:#0a1628;">This is a big opportunity.</p>
          <p style="margin:0 0 18px;">If you fully commit yourself to the process — as a player, teammate, leader, and young man — this experience can truly become a major stepping stone in both your baseball career and your life.</p>
          <p style="margin:0 0 18px;">At Ambassadors Baseball, we believe God has a purpose and plan for every player. Our job is to trust Him, work hard, stay grateful, and give our best effort every single day.</p>
          <p style="margin:0 0 18px;">Now that you are officially registered, there are a couple important "next step" items you need to complete as soon as possible:</p>

          <!-- Numbered next-step list -->
          <ol style="padding-left:24px;margin:0 0 22px;">
            <li style="margin-bottom:18px;padding-left:6px;">
              <strong style="color:#0a1628;font-size:16px;">Join The HUB</strong><br/>
              <span>The HUB is where players receive important updates, communication, schedules, training information, and announcements.</span><br/>
              <em style="color:#5a6a7a;font-style:normal;"><a href="https://portal.theambassadorsgroup.com" style="color:#c8102e;text-decoration:underline;font-weight:600;">Click here</a></em>
            </li>
            <li style="padding-left:6px;">
              <strong style="color:#0a1628;font-size:16px;">Complete Your VTS (Video Training Series)</strong><br/>
              <span>The VTS will introduce you to the Ambassadors culture, standards, expectations, and mindset. This is an important part of becoming an Ambassadors player and should be completed promptly.</span><br/>
              <span>You will find the Training Course in the Hub when you set up your new account.</span>
            </li>
          </ol>

          <p style="margin:0 0 18px;">Most importantly, take pride in being part of Ambassadors Baseball. Represent your family, your teammates, and your faith the right way both on and off the field.</p>

          <!-- Callout: key motto -->
          <p style="margin:24px 0;padding:16px 22px;border-left:3px solid #c8102e;background:#f8f9fb;font-weight:700;color:#0a1628;">Be coachable. Be accountable. Be grateful. Compete hard. Trust God's plan.</p>

          <p style="margin:0 0 18px;">We're excited to get started.</p>
          <p style="margin:24px 0 0;font-size:17px;font-weight:700;color:#0a1628;">Welcome to the family!</p>

          <!-- Signature -->
          <div style="margin-top:32px;padding-top:24px;border-top:1px solid #e3e8ef;">
            <p style="margin:0 0 4px;font-size:18px;font-weight:700;color:#0a1628;">Mark Helsel</p>
            <p style="margin:0 0 10px;color:#5a6a7a;font-style:italic;font-size:14px;">"Coach Mark"</p>
            <p style="margin:0;color:#0a1628;font-weight:600;font-size:14px;">Founder, Ambassadors Baseball</p>
          </div>
        </div>

      </div>
    </div>`;

  try {
    await createTransporter().sendMail({
      from: `"Ambassadors Baseball" <${process.env.EMAIL_USER}>`,
      to: playerEmail,
      subject: 'Welcome to Ambassadors Baseball',
      text,
      html,
    });
    console.log(`📧  Player welcome email sent — to=${playerEmail}`);
  } catch (err) {
    console.error('⚠️  Failed to send player welcome email:', err.message);
  }
}

// ── PARENT WELCOME EMAIL ──────────────────────────────────────
// Sent individually to each parent (one call per parent — mother and father each get
// their own personalized email with their own first name in the greeting).
async function sendParentWelcomeEmail({ parentEmail, parentFirstName, coachFullName }) {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.warn('⚠️  EMAIL_USER / EMAIL_PASS not set — skipping parent welcome email');
    return;
  }
  if (!parentEmail) {
    // Silent skip — not every player has both parent emails on file.
    return;
  }
  const greetingName = (parentFirstName || '').trim() || 'Parent';
  const coachName    = (coachFullName  || '').trim() || 'your coach';

  // Plain-text body (preserves the exact wording from the spec).
  const text =
`Dear ${greetingName},

First, thank you for trusting Ambassadors Baseball with your son and your family. I know you had many options, and I want you to know that I do not take your decision lightly.

For many reasons, I truly believe you made a great decision joining the Ambassadors family. Your head coach ${coachName} is an amazing man. I personally interviewed and vetted him. He is the right man to lead this team. I'm excited for you to see him in action.

Our mission goes far beyond wins and losses. We are committed to building young men of character, faith, discipline, leadership, and excellence—on and off the field. We hold ourselves to a high standard because your family deserves nothing less.

As the Founder and National Director of Ambassadors Baseball, I want you to hear this directly from me: the buck stops with me.

That means if something is not what we said it would be… if communication breaks down… if standards are not being upheld… or if you simply need guidance, encouragement, or clarity, I want you to feel completely confident reaching out to me personally. That's why I put my personal contact information below.

We are not perfect, but we are committed.

We will work hard to create an environment where players are challenged, encouraged, developed, and cared for. We expect our coaches, players, and families to represent Ambassadors with integrity and respect at all times. Protecting that culture is incredibly important to me.

Most importantly, I want you to know that you are not alone on this journey. Youth sports can be exciting, emotional, rewarding, and sometimes difficult. My goal is to help support your family through all of it.

Thank you again for believing in what we are building together.

I'm excited for the journey ahead. You will be receiving a series of emails from us. Each email contains very important information so please take care to read each one.

With gratitude,
Mark Helsel aka "Coach Mark"
Founder, Ambassadors Baseball
Email: mark@markhelsel.com
Phone: 814-502-9799`;

  // HTML version — same content, light formatting.
  const html = `
    <div style="background:#ffffff;padding:0;margin:0;">
      <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;max-width:620px;margin:0 auto;background:#ffffff;color:#1a1a2e;line-height:1.75;font-size:15px;">

        <!-- Banner -->
        <div style="background:#0a1628;padding:28px 32px;text-align:center;border-bottom:3px solid #c8102e;">
          <h1 style="color:#ffffff;margin:0;font-size:18px;letter-spacing:0.18em;text-transform:uppercase;font-weight:700;">Ambassadors Baseball</h1>
          <p style="color:#a8b5c4;margin:8px 0 0;font-size:11px;letter-spacing:0.2em;text-transform:uppercase;">A Letter from the Founder</p>
        </div>

        <!-- Body -->
        <div style="padding:40px 36px;background:#ffffff;">
          <p style="margin:0 0 20px;">Dear <strong>${greetingName}</strong>,</p>

          <p style="margin:0 0 20px;">First, thank you for trusting Ambassadors Baseball with your son and your family. I know you had many options, and I want you to know that I do not take your decision lightly.</p>

          <p style="margin:0 0 20px;">For many reasons, I truly believe you made a great decision joining the Ambassadors family. Your head coach <strong style="color:#0a1628;">${coachName}</strong> is an amazing man. I personally interviewed and vetted him. He is the right man to lead this team. I'm excited for you to see him in action.</p>

          <p style="margin:0 0 20px;">Our mission goes far beyond wins and losses. We are committed to building young men of character, faith, discipline, leadership, and excellence—on and off the field. We hold ourselves to a high standard because your family deserves nothing less.</p>

          <p style="margin:0 0 20px;">As the Founder and National Director of Ambassadors Baseball, I want you to hear this directly from me: <strong style="color:#0a1628;">the buck stops with me.</strong></p>

          <p style="margin:0 0 20px;">That means if something is not what we said it would be… if communication breaks down… if standards are not being upheld… or if you simply need guidance, encouragement, or clarity, I want you to feel completely confident reaching out to me personally. That's why I put my personal contact information below.</p>

          <!-- Callout: mission statement -->
          <p style="margin:24px 0;padding:14px 22px;border-left:3px solid #c8102e;background:#f8f9fb;font-style:italic;color:#0a1628;font-size:16px;">We are not perfect, but we are committed.</p>

          <p style="margin:0 0 20px;">We will work hard to create an environment where players are challenged, encouraged, developed, and cared for. We expect our coaches, players, and families to represent Ambassadors with integrity and respect at all times. Protecting that culture is incredibly important to me.</p>

          <p style="margin:0 0 20px;">Most importantly, I want you to know that you are not alone on this journey. Youth sports can be exciting, emotional, rewarding, and sometimes difficult. My goal is to help support your family through all of it.</p>

          <p style="margin:0 0 20px;">Thank you again for believing in what we are building together.</p>

          <p style="margin:0 0 30px;">I'm excited for the journey ahead. You will be receiving a series of emails from us. Each email contains very important information so please take care to read each one.</p>

          <!-- Signature -->
          <div style="margin-top:32px;padding-top:24px;border-top:1px solid #e3e8ef;">
            <p style="margin:0 0 6px;color:#5a6a7a;">With gratitude,</p>
            <p style="margin:0 0 4px;font-size:18px;font-weight:700;color:#0a1628;">Mark Helsel</p>
            <p style="margin:0 0 10px;color:#5a6a7a;font-style:italic;font-size:14px;">aka "Coach Mark"</p>
            <p style="margin:0 0 14px;color:#0a1628;font-weight:600;font-size:14px;">Founder, Ambassadors Baseball</p>
            <p style="margin:0;font-size:14px;color:#5a6a7a;">
              Email: <a href="mailto:mark@markhelsel.com" style="color:#c8102e;text-decoration:none;font-weight:600;">mark@markhelsel.com</a>
              <span style="margin:0 10px;color:#dce3ec;">|</span>
              Phone: <a href="tel:8145029799" style="color:#5a6a7a;text-decoration:none;">814-502-9799</a>
            </p>
          </div>

        </div>
      </div>
    </div>`;

  try {
    await createTransporter().sendMail({
      from: `"Ambassadors Baseball" <${process.env.EMAIL_USER}>`,
      to: parentEmail,
      subject: 'Welcome to Ambassadors Baseball',
      text,
      html,
    });
    console.log(`📧  Parent welcome email sent — to=${parentEmail} greeting="${greetingName}"`);
  } catch (err) {
    console.error('⚠️  Failed to send parent welcome email:', err.message);
  }
}

// ── COACH TRYOUT NOTIFICATION EMAIL ───────────────────────────────
// Fires on EVERY tryout registration — free or paid (paid: after Stripe confirms).
// Body is shared between coach + Mark; `subject` and `recipients` are passed in
// so each audience can have their own subject line (coach: short congrats;
// Mark: detailed "with Coach X (Team Y)" format).
async function sendCoachTryoutNotificationEmail({
  subject, recipients,
  coachName, teamName,
  registrantName, registrantCell, registrantEmail,
  playerName, age, dob, pos1, pos2, hw,
  address, city, state, zip, tryoutDate, isPaid, amount,
}) {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.warn('⚠️  EMAIL_USER / EMAIL_PASS not set — skipping coach tryout notification email');
    return;
  }
  if (!recipients) {
    console.log('ℹ️  No recipients for coach tryout notification — skipping');
    return;
  }
  const pos = [pos1, pos2].filter(Boolean).join(' / ') || '—';
  const loc = [city, state].filter(Boolean).join(', ') || '—';
  const statusLabel = isPaid ? 'Paid' : 'Free';
  // Currency formatter — only used for paid tryouts. Free tryouts show "Free".
  const fmtAmount = n => '$' + (parseFloat(n) || 0).toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const amountDisplay = isPaid ? (amount != null ? fmtAmount(amount) : '—') : 'Free';
  const html = `
    <div style="background:#ffffff;padding:0;margin:0;">
      <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;max-width:620px;margin:0 auto;background:#ffffff;color:#1a1a2e;line-height:1.6;font-size:14px;">

        <!-- Banner -->
        <div style="background:#0a1628;padding:24px 32px;text-align:center;border-bottom:3px solid #c8102e;">
          <h1 style="color:#ffffff;margin:0;font-size:17px;letter-spacing:0.16em;text-transform:uppercase;font-weight:700;">Ambassadors Baseball</h1>
          <p style="color:#a8b5c4;margin:6px 0 0;font-size:11px;letter-spacing:0.2em;text-transform:uppercase;">New Tryout Registration</p>
        </div>

        <!-- Body -->
        <div style="padding:30px 32px;background:#ffffff;">
          <p style="margin:0 0 22px;font-size:15px;">A new player has just registered for your tryout.</p>

          <table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:20px;">
            <tr style="background:#f4f6f9;"><td style="padding:9px 12px;color:#5a6a7a;width:42%;">Team</td><td style="padding:9px 12px;color:#0a1628;font-weight:700;">${teamName || '—'}</td></tr>
            <tr><td style="padding:9px 12px;color:#5a6a7a;">Coach Name</td><td style="padding:9px 12px;color:#0a1628;">${coachName || '—'}</td></tr>
            <tr style="background:#f4f6f9;"><td style="padding:9px 12px;color:#5a6a7a;">Tryout Date</td><td style="padding:9px 12px;color:#0a1628;font-weight:700;">${tryoutDate || '—'}</td></tr>
            <tr><td style="padding:9px 12px;color:#5a6a7a;">Registration Type</td><td style="padding:9px 12px;color:${isPaid ? '#2d7a2d' : '#0a1628'};font-weight:700;">${statusLabel}</td></tr>
            <tr style="background:#f4f6f9;"><td style="padding:9px 12px;color:#5a6a7a;">Amount</td><td style="padding:9px 12px;color:${isPaid ? '#2d7a2d' : '#0a1628'};font-weight:700;">${amountDisplay}</td></tr>
          </table>

          <h3 style="margin:24px 0 10px;font-size:13px;color:#5a6a7a;text-transform:uppercase;letter-spacing:0.08em;">Player</h3>
          <table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:20px;">
            <tr style="background:#f4f6f9;"><td style="padding:9px 12px;color:#5a6a7a;width:42%;">Player Name</td><td style="padding:9px 12px;color:#0a1628;font-weight:700;">${playerName || '—'}</td></tr>
            <tr><td style="padding:9px 12px;color:#5a6a7a;">Age</td><td style="padding:9px 12px;color:#0a1628;">${age || '—'}</td></tr>
            <tr style="background:#f4f6f9;"><td style="padding:9px 12px;color:#5a6a7a;">Date of Birth</td><td style="padding:9px 12px;color:#0a1628;">${dob || '—'}</td></tr>
            <tr><td style="padding:9px 12px;color:#5a6a7a;">Height / Weight</td><td style="padding:9px 12px;color:#0a1628;">${hw || '—'}</td></tr>
            <tr style="background:#f4f6f9;"><td style="padding:9px 12px;color:#5a6a7a;">Positions</td><td style="padding:9px 12px;color:#0a1628;">${pos}</td></tr>
          </table>

          <h3 style="margin:24px 0 10px;font-size:13px;color:#5a6a7a;text-transform:uppercase;letter-spacing:0.08em;">Registered By</h3>
          <table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:8px;">
            <tr style="background:#f4f6f9;"><td style="padding:9px 12px;color:#5a6a7a;width:42%;">Name</td><td style="padding:9px 12px;color:#0a1628;font-weight:700;">${registrantName || '—'}</td></tr>
            <tr><td style="padding:9px 12px;color:#5a6a7a;">Phone</td><td style="padding:9px 12px;color:#0a1628;">${registrantCell || '—'}</td></tr>
            <tr style="background:#f4f6f9;"><td style="padding:9px 12px;color:#5a6a7a;">Email</td><td style="padding:9px 12px;color:#0a1628;">${registrantEmail || '—'}</td></tr>
            <tr><td style="padding:9px 12px;color:#5a6a7a;">Address</td><td style="padding:9px 12px;color:#0a1628;">${address || '—'}</td></tr>
            <tr style="background:#f4f6f9;"><td style="padding:9px 12px;color:#5a6a7a;">Location</td><td style="padding:9px 12px;color:#0a1628;">${loc}</td></tr>
            <tr><td style="padding:9px 12px;color:#5a6a7a;">Zip</td><td style="padding:9px 12px;color:#0a1628;">${zip || '—'}</td></tr>
          </table>

          <p style="color:#5a6a7a;font-size:12px;margin:24px 0 0;">This is an automated notification from Ambassadors Baseball.</p>
        </div>
      </div>
    </div>`;
  try {
    await createTransporter().sendMail({
      from: `"Ambassadors Baseball" <${process.env.EMAIL_USER}>`,
      to: recipients,
      subject,
      html,
    });
    console.log(`📧  Coach tryout notification email sent — to=${recipients} player="${playerName}" subject="${subject}"`);
  } catch (err) {
    console.error('⚠️  Failed to send coach tryout notification email:', err.message);
  }
}

// ── ENV VALIDATION ────────────────────────────────────────────────
const REQUIRED_ENV = ['MONGODB_URI', 'JWT_SECRET'];
// GHL_API_KEY / GHL_LOCATION_ID are optional — used only for contact upserts
// STRIPE_SECRET_KEY is optional — needed for checkout but not fatal at startup
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length) {
  console.error('❌  Missing required environment variables:', missingEnv.join(', '));
  // Note: process.exit() not used in serverless — missing vars will surface as runtime errors
}

const app = express();
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.options('*', cors());

// ── STRIPE WEBHOOK — must receive raw body, register BEFORE express.json() ──
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe) return res.status(500).json({ message: 'Stripe not configured' });

  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('⚠️  Stripe webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    // playerPaymentId may be reassigned below after materializing a pending registration.
    let { playerPaymentId, pendingId, paymentType, coachId } = session.metadata || {};
    const amountPaid = session.amount_total / 100; // cents → dollars

    // ── Installment subscription: set cancel_at_period_end as a safety net ─
    // We primarily cancel via totalMonths count in invoice.payment_succeeded.
    // cancel_at_period_end is a backup in case the final webhook is missed —
    // it cancels cleanly at the end of the last billing period, no proration.
    if (paymentType === 'installment' && session.subscription && stripe) {
      try {
        const totalMonths = parseInt(session.metadata?.totalMonths || '0', 10);
        if (totalMonths > 0) {
          console.log(`📅  Subscription ${session.subscription} will auto-cancel after ${totalMonths} payments`);
        }
      } catch (subErr) {
        console.error('⚠️  Failed to log installment setup:', subErr.message);
      }
    }

    // ── PENDING REGISTRATION → materialize Player + PlayerPayment ─────────
    // If this checkout came from a pre-payment registration form, no Player or
    // PlayerPayment exists yet. Create them now, push to GHL, then continue
    // into the existing PlayerPayment update flow with the freshly-minted id.
    if (pendingId && !playerPaymentId) {
      try {
        const pending = await PendingRegistration.findById(pendingId).lean();
        if (!pending) {
          console.error(`❌  [WEBHOOK] PendingRegistration ${pendingId} not found — payment received but no record to materialize. Manual reconciliation needed for session ${session.id}.`);
        } else {
          const p = pending.player_payload || {};
          console.log(`📦  [WEBHOOK] Materializing pending registration ${pendingId} for player="${p.name}"`);

          // 1. Create the Player record
          const player = await Player.create({
            coach_id:     pending.coach_id,
            name:         p.name        || '',
            jersey:       p.jersey      || '',
            jersey_2:     p.jersey2     || '',
            grad_year:    p.gradYear    || '',
            position:     p.position    || '',
            pos2:         p.pos2        || '',
            hw:           p.hw          || '',
            city:         p.city        || '',
            state:        p.state       || '',
            address:      p.address     || '',
            zip:          p.zip         || '',
            email:        p.email       || '',
            cell:         p.cell        || '',
            dob:          p.dob         || '',
            bats:         p.bats        || '',
            throws:       p.throws      || '',
            high_school:  p.highSchool  || '',
            mother_first: p.motherFirst || '',
            mother_last:  p.motherLast  || '',
            mother_cell:  p.motherCell  || '',
            mother_email: p.motherEmail || '',
            father_first: p.fatherFirst || '',
            father_last:  p.fatherLast  || '',
            father_cell:  p.fatherCell  || '',
            father_email: p.fatherEmail || '',
          });
          console.log(`✅  [WEBHOOK] Player created — playerId=${player._id}`);

          // 2. Create the PlayerPayment record (status: Pending — the rest of the
          // webhook flow below will flip it to Paid/Partial with the real amount).
          const playerPayment = await PlayerPayment.create({
            coach_id:         pending.coach_id,
            player_id:        player._id,
            player_name:      p.name || '',
            total_fee:        pending.total_fee      || 0,
            deposit_amount:   pending.deposit_amount || 0,
            deposit_paid:     false,
            payment_plan:     pending.payment_plan   || [],
            amount_paid:      0,
            balance:          pending.total_fee      || 0,
            status:           'Pending',
            registered_date:  pending.registered_date || '',
            payment_deadline: pending.payment_deadline || '',
          });
          console.log(`✅  [WEBHOOK] PlayerPayment created — playerPaymentId=${playerPayment._id}`);

          // 3. Push to GHL (best-effort — never blocks the materialization).
          try {
            await upsertGHLPlayer({
              name:        p.name,
              email:       p.email,
              cell:        p.cell,
              dob:         p.dob,
              bats:        p.bats,
              throws:      p.throws,
              hw:          p.hw,
              jersey:      p.jersey,
              jersey2:     p.jersey2,
              gradYear:    p.gradYear,
              position:    p.position,
              pos2:        p.pos2,
              address:     p.address,
              city:        p.city,
              state:       p.state,
              zip:         p.zip,
              highSchool:  p.highSchool,
              motherFirst: p.motherFirst,
              motherLast:  p.motherLast,
              motherCell:  p.motherCell,
              motherEmail: p.motherEmail,
              fatherFirst: p.fatherFirst,
              fatherLast:  p.fatherLast,
              fatherCell:  p.fatherCell,
              fatherEmail: p.fatherEmail,
              teamName:    pending.team_name || '',
            });
          } catch (ghlErr) {
            // Already logged inside upsertGHLPlayer; swallow so DB stays consistent.
            console.error('⚠️  [WEBHOOK] GHL push failed but DB records created:', ghlErr.message);
          }

          // 4. For installments: backfill playerPaymentId onto the Stripe subscription
          // metadata so subsequent invoice.payment_succeeded webhooks can find the
          // PlayerPayment row. Without this, only the first installment would be
          // recorded — every recurring charge would be silently lost in the DB.
          if (paymentType === 'installment' && session.subscription && stripe) {
            try {
              const existingSub = await stripe.subscriptions.retrieve(session.subscription);
              await stripe.subscriptions.update(session.subscription, {
                metadata: {
                  ...(existingSub.metadata || {}),
                  playerPaymentId: String(playerPayment._id),
                },
              });
              console.log(`🔗  [WEBHOOK] Subscription ${session.subscription} metadata backfilled with playerPaymentId=${playerPayment._id}`);
            } catch (metaErr) {
              console.error('⚠️  [WEBHOOK] Failed to backfill subscription metadata:', metaErr.message);
              // Non-fatal — first payment still recorded below via session metadata.
              // Recurring charges would need manual reconciliation if this fails.
            }
          }

          // 5. Delete the pending row — we no longer need it.
          await PendingRegistration.findByIdAndDelete(pendingId);
          console.log(`🗑️   [WEBHOOK] PendingRegistration ${pendingId} deleted`);

          // 6. Hand off to the existing PlayerPayment update flow below.
          playerPaymentId = String(playerPayment._id);
        }
      } catch (matErr) {
        console.error('❌  [WEBHOOK] Materialization error:', matErr.message);
        // Return 500 so Stripe retries automatically (up to 17 times over 3 days).
        // The pending row is preserved (we didn't delete it) so each retry is safe.
        return res.status(500).send('Materialization failed — will retry');
      }
    }

    if (playerPaymentId) {
      try {
        const existing = await PlayerPayment.findById(playerPaymentId);
        if (existing) {
          const today = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
          const update = {};

          if (paymentType === 'deposit') {
            const newAmountPaid = (existing.amount_paid || 0) + amountPaid;
            const newBalance    = Math.max(0, (existing.total_fee || 0) - newAmountPaid);
            update.deposit_paid      = true;
            update.deposit_paid_date = today;
            update.amount_paid       = newAmountPaid;
            update.balance           = newBalance;
            update.status            = newBalance <= 0 ? 'Paid' : 'Partial';
          } else if (paymentType === 'full' || paymentType === 'remainder') {
            // If a coupon discounted this charge, record the ACTUAL dollars
            // received (prior payments + this discounted charge) instead of
            // assuming full fee — the account is still settled (balance 0,
            // status Paid) because the coupon covers the difference.
            const discountApplied = (session.total_details?.amount_discount || 0) > 0;
            update.amount_paid = discountApplied
              ? Math.min(existing.total_fee || 0, (existing.amount_paid || 0) + amountPaid)
              : existing.total_fee;
            update.balance     = 0;
            update.status      = 'Paid';
            if (paymentType === 'deposit') {
              update.deposit_paid      = true;
              update.deposit_paid_date = today;
            }
          } else if (paymentType === 'installment') {
            const newAmountPaid = (existing.amount_paid || 0) + amountPaid;
            const newBalance    = Math.max(0, (existing.total_fee || 0) - newAmountPaid);
            update.amount_paid = newAmountPaid;
            update.balance     = newBalance;
            update.status      = newBalance <= 0 ? 'Paid' : 'Partial';
          }

          await PlayerPayment.findByIdAndUpdate(playerPaymentId, update);
          console.log(`✅  Stripe payment recorded — playerPaymentId=${playerPaymentId} type=${paymentType}`);

          // ── Send payment notification emails ──────────────────
          // 1) Coach — table notification, congratulations subject
          // 2) Jahirul + Sajeeb — same table body, internal staff subject
          // 3) Player — welcome letter
          // 4) Father / Mother — separate personalized welcome letter (one each)
          //
          // Each send is wrapped in its own try/catch so a failure on one
          // recipient never blocks the others or the rest of the webhook.
          try {
            const updatedPmt = await PlayerPayment.findById(playerPaymentId);
            const playerRec  = updatedPmt?.player_id
              ? await Player.findById(updatedPmt.player_id).select('name email cell father_first father_email mother_first mother_email')
              : null;
            const coachRec   = updatedPmt?.coach_id
              ? await Coach.findById(updatedPmt.coach_id).select('first_name last_name team_name email')
              : null;

            const coachFullName = coachRec ? `${coachRec.first_name || ''} ${coachRec.last_name || ''}`.trim() : '';
            const teamName      = coachRec?.team_name || '';
            const playerName    = updatedPmt?.player_name || playerRec?.name || '';

            // Shared payload for the staff/coach table emails.
            const tablePayload = {
              playerName,
              paymentType,
              amountPaid:  updatedPmt?.amount_paid ?? 0,
              totalFee:    updatedPmt?.total_fee   ?? 0,
              balance:     updatedPmt?.balance     ?? 0,
              status:      updatedPmt?.status      || '',
              playerEmail: playerRec?.email        || '',
              playerCell:  playerRec?.cell         || '',
              coachName:   coachFullName,
              teamName,
            };

            // (1) Coach notification — congratulations subject.
            if (coachRec?.email) {
              try {
                await sendPaymentNotificationEmail({
                  ...tablePayload,
                  subject:    'Congratulations! Another player has accepted your invitation and has registered for your team.',
                  recipients: coachRec.email,
                });
              } catch (e) { console.error('⚠️  Coach notification email error:', e.message); }
            }

            // (2) Jahirul + Sajeeb — internal staff subject (same body).
            try {
              const staffSubject = `New Player Registration — ${playerName || 'Player'} with Coach ${coachFullName || 'Unknown'} (${teamName || 'Unknown Team'})`;
              await sendPaymentNotificationEmail({
                ...tablePayload,
                subject:    staffSubject,
                recipients: 'jahirul@appsus.io, mark@markhelsel.com',
              });
            } catch (e) { console.error('⚠️  Staff notification email error:', e.message); }

            // (3) Player welcome email.
            if (playerRec?.email) {
              try {
                await sendPlayerWelcomeEmail({
                  playerEmail: playerRec.email,
                  playerName,
                });
              } catch (e) { console.error('⚠️  Player welcome email error:', e.message); }
            }

            // (4) Parent welcome emails — one per parent, individually addressed.
            if (playerRec?.father_email) {
              try {
                await sendParentWelcomeEmail({
                  parentEmail:     playerRec.father_email,
                  parentFirstName: playerRec.father_first || '',
                  coachFullName,
                });
              } catch (e) { console.error('⚠️  Father welcome email error:', e.message); }
            }
            if (playerRec?.mother_email) {
              try {
                await sendParentWelcomeEmail({
                  parentEmail:     playerRec.mother_email,
                  parentFirstName: playerRec.mother_first || '',
                  coachFullName,
                });
              } catch (e) { console.error('⚠️  Mother welcome email error:', e.message); }
            }
          } catch (emailErr) {
            console.error('⚠️  Payment notification email block error (checkout):', emailErr.message);
          }
        }
      } catch (dbErr) {
        console.error('❌  Failed to update PlayerPayment after Stripe webhook:', dbErr.message);
      }
    }

    // ── Tryout payment confirmed ──────────────────────────────────────────────
    if (paymentType === 'tryout') {
      const { registrationId } = session.metadata || {};
      if (registrationId) {
        // Flip status to 'confirmed' and capture the updated doc in one query.
        // Once status='confirmed', the partial TTL index no longer matches this
        // document — it's now permanent and will not be auto-deleted.
        let confirmedReg = null;
        try {
          confirmedReg = await TryoutRegistration.findByIdAndUpdate(
            registrationId,
            { status: 'confirmed' },
            { new: true }
          );
          console.log(`✅  Tryout registration confirmed — registrationId=${registrationId}`);
        } catch (dbErr) {
          console.error('❌  Failed to confirm tryout registration:', dbErr.message);
        }

        if (confirmedReg) {
          // ── GHL upsert (paid tryout) ──────────────────────────────────
          // Only runs after payment is confirmed. Abandoned checkouts never
          // reach the webhook → GHL stays clean of failed registrations.
          try {
            await upsertGHLContact({
              completedBy: confirmedReg.completed_by,
              name:        confirmedReg.name,
              address:     confirmedReg.address,
              city:        confirmedReg.city,
              state:       confirmedReg.state,
              zip:         confirmedReg.zip,
              cell:        confirmedReg.cell,
              email:       confirmedReg.email,
              playerName:  confirmedReg.player_name,
              age:         confirmedReg.age,
              dob:         confirmedReg.dob,
              hw:          confirmedReg.hw,
              pos1:        confirmedReg.pos1,
              pos2:        confirmedReg.pos2,
              tryoutDate:  confirmedReg.tryout_date,
            });
            console.log(`✅  GHL upsert completed for paid tryout — registrationId=${registrationId}`);
          } catch (ghlErr) {
            console.error('⚠️  GHL upsert error (paid tryout):', ghlErr.message);
          }

          // ── Notify coach + Mark (paid tryout) ─────────────────────────
          // Two sends, same body, different subjects:
          //   1) Coach: short congrats subject (only if they have an email)
          //   2) Mark:  detailed subject with player + coach + team
          // Each send wrapped in its own try/catch so one failure never blocks the other.
          const coachRec = await Coach.findById(confirmedReg.coach_id).select('first_name last_name team_name email').catch(() => null);
          const coachFullName = coachRec ? `${coachRec.first_name || ''} ${coachRec.last_name || ''}`.trim() : '';
          const teamName      = coachRec?.team_name || '';
          const playerName    = confirmedReg.player_name || '';

          const tryoutPayload = {
            coachName:       coachFullName,
            teamName,
            registrantName:  confirmedReg.name,
            registrantCell:  confirmedReg.cell,
            registrantEmail: confirmedReg.email,
            playerName,
            age:             confirmedReg.age,
            dob:             confirmedReg.dob,
            pos1:            confirmedReg.pos1,
            pos2:            confirmedReg.pos2,
            hw:              confirmedReg.hw,
            address:         confirmedReg.address,
            city:            confirmedReg.city,
            state:           confirmedReg.state,
            zip:             confirmedReg.zip,
            tryoutDate:      confirmedReg.tryout_date,
            isPaid:          true,
            // Actual amount paid (Stripe cents → dollars). Reflects what was
            // really charged in case the coach changed the price mid-flight.
            amount:          (session.amount_total || 0) / 100,
          };

          // (1) Coach — short congrats subject
          if (coachRec?.email) {
            try {
              await sendCoachTryoutNotificationEmail({
                ...tryoutPayload,
                subject:    'Congratulations! A new player has registered for your tryout.',
                recipients: coachRec.email,
              });
            } catch (e) { console.error('⚠️  Coach tryout email error (paid, coach):', e.message); }
          }

          // (2) Mark — detailed subject
          try {
            const markSubject = `New Tryout Registration — ${playerName || 'Player'} with Coach ${coachFullName || 'Unknown'} (${teamName || 'Unknown Team'})`;
            await sendCoachTryoutNotificationEmail({
              ...tryoutPayload,
              subject:    markSubject,
              recipients: 'mark@markhelsel.com',
            });
          } catch (e) { console.error('⚠️  Coach tryout email error (paid, mark):', e.message); }
        }
      }
    }
  }

  // ── Monthly installment payment succeeded ─────────────────────────────────
  // Handles both old API (invoice.payment_succeeded) and new API (invoice_payment.paid)
  // invoice_payment.paid was introduced in Stripe API version 2026-02-25
  if (event.type === 'invoice.payment_succeeded' || event.type === 'invoice_payment.paid') {
    const isNewFormat = event.type === 'invoice_payment.paid';
    const rawObj      = event.data.object;

    // invoice_payment.paid has a different shape — fetch the parent invoice
    // to get billing_reason and subscription ID
    let invoice;
    if (isNewFormat) {
      try {
        invoice = await stripe.invoices.retrieve(rawObj.invoice);
        console.log(`🔔  invoice_payment.paid — invoice=${rawObj.invoice} amount=${rawObj.amount_paid} billing_reason=${invoice.billing_reason} sub=${invoice.subscription}`);
      } catch (fetchErr) {
        console.error('❌  Could not fetch invoice for invoice_payment.paid:', fetchErr.message);
        return res.json({ received: true });
      }
    } else {
      invoice = rawObj;
      console.log(`🔔  invoice.payment_succeeded — billing_reason=${invoice.billing_reason} amount=${invoice.amount_paid} sub=${invoice.subscription}`);
    }

    // ── Extract subscription ID — location changed in Stripe API 2026-02-25 ──
    // Old API: invoice.subscription
    // New API: invoice.parent.subscription_details.subscription
    const subId = invoice.subscription
      || invoice?.parent?.subscription_details?.subscription
      || invoice?.parent?.subscription
      || null;

    console.log(`🔍  Resolved subId=${subId} (from invoice.subscription=${invoice.subscription} parent=${JSON.stringify(invoice.parent || null)})`);

    if (invoice.billing_reason === 'subscription_create') {
      console.log(`⏭️  Skipping — first charge already handled by checkout.session.completed`);
    } else {
      if (!subId) {
        console.error('❌  No subscription ID on invoice — cannot process');
      } else if (!stripe) {
        console.error('❌  Stripe not initialised');
      } else {
        try {
          const subscription = await stripe.subscriptions.retrieve(subId);
          console.log(`📋  Subscription metadata:`, JSON.stringify(subscription.metadata));

          const { playerPaymentId } = subscription.metadata || {};
          const totalMonths  = parseInt(subscription.metadata?.totalMonths || '0', 10);
          const amountPaid   = invoice.amount_paid / 100;

          if (!playerPaymentId) {
            console.error(`❌  No playerPaymentId in subscription metadata for ${subId} — cannot update DB`);
          } else if (amountPaid <= 0) {
            console.warn(`⚠️  amountPaid is ${amountPaid} — skipping`);
          } else {
            console.log(`🔎  Looking up PlayerPayment: ${playerPaymentId}`);
            const existing = await PlayerPayment.findById(playerPaymentId);

            if (!existing) {
              console.error(`❌  PlayerPayment ${playerPaymentId} not found in DB`);
            } else {
              console.log(`📊  Current record — total_fee=${existing.total_fee} amount_paid=${existing.amount_paid} balance=${existing.balance} status=${existing.status} installments_paid=${existing.installments_paid||0}/${totalMonths}`);

              const totalFee         = existing.total_fee || 0;
              const paidSoFar        = existing.amount_paid || 0;
              const installmentsPaid = (existing.installments_paid || 0) + 1;

              // ── Determine if this is the final payment ────────────────────
              // We use the totalMonths count stored in subscription metadata.
              // This is more reliable than comparing dollar amounts because
              // integer division always leaves a fractional cent gap that would
              // cause the last invoice to show a prorated/partial amount.
              // When it IS the last payment we zero the balance exactly —
              // the player is fully settled regardless of cent-level rounding.
              const isLastPayment = totalMonths > 0 && installmentsPaid >= totalMonths;

              let newAmountPaid, newBalance;
              if (isLastPayment) {
                // Last payment by count — zero out exactly regardless of rounding
                newAmountPaid = totalFee;
                newBalance    = 0;
                console.log(`🏁  Final installment ${installmentsPaid}/${totalMonths} — zeroing balance exactly`);
              } else {
                newAmountPaid = Math.min(paidSoFar + amountPaid, totalFee);
                newBalance    = Math.max(0, totalFee - newAmountPaid);

                // Penny tolerance — catches rounding gaps like $0.01 from
                // $1000/3 = $999.99 when totalMonths is 0 (old subscriptions
                // created before totalMonths metadata was added).
                // If balance is $0.50 or less after payment, treat as fully paid.
                if (newBalance > 0 && newBalance <= 0.50) {
                  console.log(`🪙  Balance ${newBalance} within penny tolerance — zeroing out`);
                  newAmountPaid = totalFee;
                  newBalance    = 0;
                }
              }

              const newStatus = newBalance <= 0 ? 'Paid' : 'Partial';
              console.log(`💾  Updating — installment=${installmentsPaid}/${totalMonths} isLast=${isLastPayment} newAmountPaid=${newAmountPaid} newBalance=${newBalance} newStatus=${newStatus}`);

              await PlayerPayment.findByIdAndUpdate(playerPaymentId, {
                amount_paid:       newAmountPaid,
                balance:           newBalance,
                status:            newStatus,
                installments_paid: installmentsPaid,
              });
              console.log(`✅  DB updated successfully — playerPaymentId=${playerPaymentId}`);

              // ── Handle second-to-last and last payment ────────────────
              // The problem: if the last billing cycle is shorter than 30 days
              // (e.g. registered July 10, deadline Sept 30 — last cycle is
              // Sept 10 → Sept 30 = 20 days), Stripe prorates and charges less.
              //
              // Solution: after the SECOND-TO-LAST payment, cancel the subscription
              // immediately and create a one-time invoice for the exact remaining
              // balance. This guarantees the full amount is always collected
              // regardless of how many days are left in the final cycle.
              const isSecondToLast = totalMonths > 1 && installmentsPaid === totalMonths - 1;

              if (isLastPayment || newBalance <= 0) {
                // All done — cancel subscription cleanly
                console.log(`🎉  All payments complete — cancelling subscription ${subId}`);
                try {
                  await stripe.subscriptions.cancel(subId);
                  console.log(`✅  Subscription ${subId} cancelled — fully paid`);
                } catch (cancelErr) {
                  console.error(`⚠️  Could not cancel subscription ${subId}:`, cancelErr.message);
                }

              } else if (isSecondToLast && stripe) {
                // Second-to-last payment just completed.
                // Cancel the subscription NOW and immediately invoice the exact
                // remaining balance as a one-time charge — this avoids any
                // proration on the final cycle.
                console.log(`⏭️  Second-to-last payment done — cancelling subscription and invoicing remaining balance ${newBalance}`);
                try {
                  // 1. Get the customer ID from the subscription
                  const sub        = await stripe.subscriptions.retrieve(subId);
                  const customerId = sub.customer;

                  // 2. Cancel the subscription immediately (no more auto-charges)
                  await stripe.subscriptions.cancel(subId);
                  console.log(`🚫  Subscription ${subId} cancelled after ${installmentsPaid} payments`);

                  // 3. Create a one-time invoice for the exact remaining balance
                  const remainingCents = Math.round(newBalance * 100);
                  const invoiceItem = await stripe.invoiceItems.create({
                    customer:    customerId,
                    amount:      remainingCents,
                    currency:    'usd',
                    description: `Final installment — remaining balance`,
                    metadata:    { playerPaymentId, subId },
                  });

                  const finalInvoice = await stripe.invoices.create({
                    customer:          customerId,
                    auto_advance:      true, // automatically charge the card on file
                    collection_method: 'charge_automatically',
                    metadata:          { playerPaymentId, paymentType: 'installment_final', coachId: subscription.metadata?.coachId || '' },
                  });

                  await stripe.invoices.finalizeInvoice(finalInvoice.id);
                  await stripe.invoices.pay(finalInvoice.id);
                  console.log(`💳  Final invoice ${finalInvoice.id} created and charged — ${newBalance}`);

                } catch (finalErr) {
                  console.error(`❌  Failed to create final invoice:`, finalErr.message);
                  // Subscription is already cancelled at this point.
                  // The player will need to pay the remaining balance manually.
                }
              }
            }
          }
        } catch (err) {
          console.error('❌  Failed to process invoice.payment_succeeded:', err.message);
          console.error(err.stack);
        }
      }
    }
  }

  // ── Subscription cancelled (user cancelled or Stripe auto-cancelled at deadline) ──
  if (event.type === 'customer.subscription.deleted') {
    const subscription = event.data.object;
    const { playerPaymentId } = subscription.metadata || {};

    if (playerPaymentId) {
      try {
        const existing = await PlayerPayment.findById(playerPaymentId);
        if (existing && existing.status !== 'Paid') {
          const balance = Math.max(0, (existing.total_fee || 0) - (existing.amount_paid || 0));
          // Only mark Cancelled if there's still an outstanding balance.
          // If balance is 0 the subscription ended naturally after all payments — leave as Paid.
          const status = balance > 0 ? 'Cancelled' : 'Paid';
          await PlayerPayment.findByIdAndUpdate(playerPaymentId, { status, balance });
          console.log(`🚫  Subscription ${subscription.id} ended — playerPaymentId=${playerPaymentId} status=${status} balance=${balance}`);
        }
      } catch (err) {
        console.error('❌  Failed to update PlayerPayment on subscription cancel:', err.message);
      }
    }
  }

  res.json({ received: true });
});

app.use(express.json({ limit: '10mb' }));

// ── MONGODB CONNECTION ────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅  MongoDB connected'))
  .catch(err => { console.error('❌  MongoDB connection error:', err); process.exit(1); });

// ════════════════════════════════════════════════════════════════
//  MONGOOSE SCHEMAS & MODELS
// ════════════════════════════════════════════════════════════════

const coachSchema = new mongoose.Schema({
  first_name:   { type: String, required: true },
  last_name:    { type: String, required: true },
  email:        { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone:        { type: String, default: '' },
  team_name:    { type: String, default: '' },
  state:        { type: String, default: '' },
  location:     { type: String, default: '' },
  age_group:    { type: String, default: '' },
  password:     { type: String, required: true },
  email_public: { type: String, default: '' },
  phone_public: { type: String, default: '' },
  bio:          { type: String, default: '' },
  image_url:    { type: String, default: '' },
  team_details:     { type: String,  default: '' },
  register_enabled: { type: Boolean, default: true },
  assistant1:   { type: mongoose.Schema.Types.Mixed, default: {} },
  assistant2:   { type: mongoose.Schema.Types.Mixed, default: {} },
  active:             { type: Boolean, default: true },
  otp_code:           { type: String,  default: null },
  otp_expiry:         { type: Date,    default: null },
  otp_purpose:        { type: String,  default: null },
  reset_token:        { type: String,  default: null },
  reset_token_expiry: { type: Date,    default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
coachSchema.index({ active: 1 });

const tryoutSchema = new mongoose.Schema({
  coach_id:          { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true },
  date:              { type: String, default: '' },
  time:              { type: String, default: '' },
  location:          { type: String, default: '' },
  fee:               { type: String, default: 'Free' },
  city:              { type: String, default: '' },
  state:             { type: String, default: '' },
  stripe_product_id: { type: String, default: '' },
  stripe_price_id:   { type: String, default: '' },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
tryoutSchema.index({ coach_id: 1 });

const tryoutRegistrationSchema = new mongoose.Schema({
  coach_id:     { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true },
  completed_by: { type: String, default: '' },
  name:         { type: String, default: '' },
  address:      { type: String, default: '' },
  city:         { type: String, default: '' },
  state:        { type: String, default: '' },
  zip:          { type: String, default: '' },
  cell:         { type: String, default: '' },
  email:        { type: String, default: '' },
  player_name:  { type: String, default: '' },
  age:          { type: String, default: '' },
  dob:          { type: String, default: '' },
  hw:           { type: String, default: '' },
  pos1:         { type: String, default: '' },
  pos2:         { type: String, default: '' },
  tryout_date:  { type: String, default: '' },
  status:       { type: String, default: 'confirmed' }, // 'confirmed' | 'pending_payment'
  // For paid tryouts only: 72h auto-cleanup if payment never completes.
  // Set when status='pending_payment' on creation. Once payment is confirmed
  // and status flips to 'confirmed', the partial TTL index below excludes the
  // document and it will NEVER be deleted — even after expires_at has passed.
  expires_at:   { type: Date,   default: undefined },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
tryoutRegistrationSchema.index({ coach_id: 1 });
// Partial TTL: auto-delete abandoned 'pending_payment' rows after 72h.
// The partialFilterExpression ensures MongoDB only considers documents where
// status='pending_payment'. As soon as the webhook flips status to 'confirmed',
// the document is excluded from this index and TTL can never delete it.
tryoutRegistrationSchema.index(
  { expires_at: 1 },
  {
    expireAfterSeconds: 0,
    partialFilterExpression: { status: 'pending_payment' },
  }
);

const playerSchema = new mongoose.Schema({
  coach_id:         { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true },
  name:             { type: String, required: true },
  jersey:           { type: String, default: '' },
  jersey_2:         { type: String, default: '' },
  grad_year:        { type: String, default: '' },
  position:         { type: String, default: '' },
  pos2:             { type: String, default: '' },
  hw:               { type: String, default: '' },
  city:             { type: String, default: '' },
  state:            { type: String, default: '' },
  address:          { type: String, default: '' },
  zip:              { type: String, default: '' },
  email:            { type: String, default: '' },
  cell:             { type: String, default: '' },
  dob:              { type: String, default: '' },
  bats:             { type: String, default: '' },
  throws:           { type: String, default: '' },
  high_school:      { type: String, default: '' },
  mother_first:     { type: String, default: '' },
  mother_last:      { type: String, default: '' },
  mother_cell:      { type: String, default: '' },
  mother_email:     { type: String, default: '' },
  father_first:     { type: String, default: '' },
  father_last:      { type: String, default: '' },
  father_cell:      { type: String, default: '' },
  father_email:     { type: String, default: '' },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
playerSchema.index({ coach_id: 1 });

const scheduleSchema = new mongoose.Schema({
  coach_id:   { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true },
  date:       { type: String, default: '' },
  start_date: { type: String, default: '' },
  end_date:   { type: String, default: '' },
  event:      { type: String, default: '' },
  city:       { type: String, default: '' },
  state:      { type: String, default: '' },
  result:     { type: String, default: 'Upcoming' },
  date_sort:  { type: String, default: '' },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
scheduleSchema.index({ coach_id: 1, date_sort: 1 });

const teamFinancialsSchema = new mongoose.Schema({
  coach_id:           { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true, unique: true },
  player_fee:         { type: Number, default: 0 },
  payment_deadline:   { type: String, default: '' },
  full_pay_only:      { type: Boolean, default: true },
  deposit_enabled:    { type: Boolean, default: false },
  deposit_amount:     { type: Number, default: 250 },
  monthly_payments:   { type: Boolean, default: false },
  installment_months: { type: Number, default: 3 },

  stripe_product_full:        { type: String, default: '' },
  stripe_product_deposit:     { type: String, default: '' },
  stripe_product_remainder:   { type: String, default: '' },
  stripe_product_installment: { type: String, default: '' },

  stripe_price_full:        { type: String, default: '' },
  stripe_price_deposit:     { type: String, default: '' },
  stripe_price_remainder:   { type: String, default: '' },
  stripe_price_installment: { type: String, default: '' },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });

const playerPaymentSchema = new mongoose.Schema({
  coach_id:          { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true },
  player_id:         { type: mongoose.Schema.Types.ObjectId, ref: 'Player', default: null },
  player_name:       { type: String, default: '' },
  total_fee:         { type: Number, default: 0 },
  deposit_amount:    { type: Number, default: 0 },
  deposit_paid:      { type: Boolean, default: false },
  deposit_paid_date: { type: String, default: '' },
  payment_plan:      { type: mongoose.Schema.Types.Mixed, default: [] },
  amount_paid:       { type: Number, default: 0 },
  balance:           { type: Number, default: 0 },
  status:            { type: String, default: 'Pending' },
  registered_date:   { type: String, default: '' },
  payment_deadline:  { type: String, default: '' },
  installments_paid: { type: Number, default: 0 }, // tracks how many monthly charges have fired
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
playerPaymentSchema.index({ coach_id: 1 });

const budgetSchema = new mongoose.Schema({
  coach_id:     { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true },
  date:         { type: String, default: '' },
  players:      { type: Number, default: 0 },
  seasons:      { type: Number, default: 0 },
  num_events:   { type: Number, default: 0 },
  event_cost:   { type: Number, default: 0 },
  tournaments:  { type: Number, default: 0 },
  head_pay:     { type: Number, default: 0 },
  asst_pay:     { type: Number, default: 0 },
  rentals:      { type: Number, default: 0 },
  gas:          { type: Number, default: 0 },
  hotel_nights: { type: Number, default: 0 },
  hotel_avg:    { type: Number, default: 0 },
  hotels:       { type: Number, default: 0 },
  num_uniforms: { type: Number, default: 0 },
  uniform_cost: { type: Number, default: 0 },
  uniforms:     { type: Number, default: 0 },
  equipment:    { type: Number, default: 0 },
  insurance:    { type: Number, default: 0 },
  ambassadors:  { type: Number, default: 0 },
  others:       { type: mongoose.Schema.Types.Mixed, default: [] },
  total:        { type: Number, default: 0 },
  per_player:   { type: Number, default: 0 },
  status:       { type: String, default: 'draft' },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
budgetSchema.index({ coach_id: 1 });

// ── PENDING REGISTRATION (pre-payment holding area) ──────────────
// Holds the registration form payload while the parent is at Stripe checkout.
// Materialized into Player + PlayerPayment + GHL push only after the
// checkout.session.completed webhook fires. Auto-expires after 48h via TTL.
const pendingRegistrationSchema = new mongoose.Schema({
  coach_id:        { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true },
  // Snapshot of every field the registration form may submit. Stored loosely
  // because two frontend forms (team.html and player-registration.html) submit
  // slightly different field sets — we accept whatever shows up.
  player_payload:  { type: Object, default: {} },
  // Snapshot of fee/deposit at submit time — used to create PlayerPayment after checkout.
  total_fee:       { type: Number, default: 0 },
  deposit_amount:  { type: Number, default: 0 },
  payment_plan:    { type: Array,  default: [] },
  payment_deadline:{ type: String, default: '' },
  registered_date: { type: String, default: '' },
  team_name:       { type: String, default: '' },
  // TTL — auto-delete after 48 hours from creation.
  // 48hrs gives breathing room vs Stripe's 24hr session expiry —
  // ensures the pending record outlives the checkout session in all cases.
  expires_at:      { type: Date,   default: () => new Date(Date.now() + 48 * 60 * 60 * 1000) },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
pendingRegistrationSchema.index({ coach_id: 1 });
// MongoDB TTL index — documents are removed when expires_at is reached.
pendingRegistrationSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });

const coachPayoutSchema = new mongoose.Schema({
  coach_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true },
  date:     { type: Date,   required: true },
  amount:   { type: Number, required: true },
  notes:    { type: String, default: '' },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
coachPayoutSchema.index({ coach_id: 1 });

// ── MODELS ────────────────────────────────────────────────────────
const Coach              = mongoose.model('Coach',              coachSchema);
const Tryout             = mongoose.model('Tryout',             tryoutSchema);
const TryoutRegistration = mongoose.model('TryoutRegistration', tryoutRegistrationSchema);
const Player             = mongoose.model('Player',             playerSchema);
const Schedule           = mongoose.model('Schedule',           scheduleSchema);
const TeamFinancials     = mongoose.model('TeamFinancials',     teamFinancialsSchema);
const PlayerPayment      = mongoose.model('PlayerPayment',      playerPaymentSchema);
const Budget             = mongoose.model('Budget',             budgetSchema);
const PendingRegistration= mongoose.model('PendingRegistration', pendingRegistrationSchema);
const CoachPayout        = mongoose.model('CoachPayout',        coachPayoutSchema);

// ════════════════════════════════════════════════════════════════
//  GHL HELPERS
// ════════════════════════════════════════════════════════════════

const GHL_HEADERS = () => ({
  'Authorization': `Bearer ${process.env.GHL_API_KEY}`,
  'Content-Type':  'application/json',
  'Accept':        'application/json',
  'Version':       '2021-07-28',
});

// ── GHL MEDIA UPLOAD ──────────────────────────────────────────
async function uploadImageToGHL(base64, fileName, mimeType) {
  const buffer = Buffer.from(base64, 'base64');
  const form   = new FormData();
  form.append('file', buffer, { filename: fileName, contentType: mimeType || 'image/jpeg' });
  form.append('fileAltText', fileName);

  const response = await axios.post(
    'https://services.leadconnectorhq.com/medias/upload-file',
    form,
    {
      headers: {
        'Authorization': `Bearer ${process.env.GHL_API_KEY}`,
        'Version':       '2021-07-28',
        ...form.getHeaders(),
      },
      params: { locationId: process.env.GHL_LOCATION_ID },
    }
  );

  const url = response.data?.url;
  if (!url) throw new Error('GHL upload succeeded but no URL returned: ' + JSON.stringify(response.data));
  return url;
}

// ── STRIPE PRODUCT + PRICE CREATION ──────────────────────────
/**
 * Creates a Stripe product and a price under it directly.
 *
 * @param {string}      name       - Display name (e.g. "Team – Full Payment ($2000)")
 * @param {number}      amount     - Dollar amount e.g. 250 (converted to cents internally)
 * @param {object|null} recurring  - null = one_time; { interval: 'month', intervalCount: 1 } = recurring
 * @returns {{ productId: string, priceId: string }}
 */
async function createStripeProductWithPrice(name, amount, recurring = null) {
  if (!stripe) throw new Error('Stripe is not configured — set STRIPE_SECRET_KEY env var');

  // ── Step 1: Create product ────────────────────────────────
  const product = await stripe.products.create({ name });
  const productId = product.id;
  console.log(`📦  Stripe product created: "${name}" → productId=${productId}`);

  // ── Step 2: Create price ──────────────────────────────────
  const priceParams = {
    product:     productId,
    unit_amount: Math.round(amount * 100), // dollars → cents
    currency:    'usd',
  };
  if (recurring) {
    priceParams.recurring = {
      interval:       recurring.interval,
      interval_count: recurring.intervalCount || 1,
    };
  }

  const price = await stripe.prices.create(priceParams);
  const priceId = price.id;
  console.log(`💰  Stripe price created: "${name}" $${amount} → priceId=${priceId}`);

  return { productId, priceId };
}

/**
 * Archives a Stripe product (and its prices) by ID. Best-effort — never throws.
 * Stripe does not allow hard-deleting products that have prices, so we archive instead.
 */
async function deleteStripeProduct(productId) {
  if (!productId || !stripe) return;
  try {
    // Unset default_price first so prices can be safely deactivated
    await stripe.products.update(productId, { default_price: '' });
    // Deactivate all active prices
    const prices = await stripe.prices.list({ product: productId, active: true, limit: 100 });
    await Promise.all(prices.data.map(p => stripe.prices.update(p.id, { active: false })));
    // Archive the product itself
    await stripe.products.update(productId, { active: false });
    console.log(`🗑️  Stripe product archived: ${productId}`);
  } catch (err) {
    console.warn(`⚠️  Could not archive Stripe product ${productId}:`, err.message);
  }
}

/**
 * Updates the price on an existing Stripe product when only the fee changes.
 * Deactivates the old price, creates a new price under the same product,
 * sets the new price as default on the product, and returns the new priceId.
 * Product ID stays the same — no archiving or recreation.
 *
 * @param {string}      productId  - Existing Stripe product ID to update
 * @param {number}      amount     - New dollar amount
 * @param {object|null} recurring  - null = one_time; recurring object = subscription
 * @returns {string} new priceId
 */
async function updateStripeProductPrice(productId, amount, recurring = null) {
  if (!productId || !stripe) throw new Error('Stripe not configured or missing productId');

  // Step 1 — Create new price first under the same product
  const priceParams = {
    product:     productId,
    unit_amount: Math.round(amount * 100),
    currency:    'usd',
  };
  if (recurring) {
    priceParams.recurring = {
      interval:       recurring.interval,
      interval_count: recurring.intervalCount || 1,
    };
  }
  const newPrice = await stripe.prices.create(priceParams);

  // Step 2 — Set new price as default (removes old price as default so it can be deactivated)
  await stripe.products.update(productId, { default_price: newPrice.id });

  // Step 3 — Now safely deactivate old prices (they are no longer the default)
  const existing = await stripe.prices.list({ product: productId, active: true, limit: 100 });
  await Promise.all(
    existing.data
      .filter(p => p.id !== newPrice.id)
      .map(p => stripe.prices.update(p.id, { active: false }))
  );

  console.log(`💰  Stripe price updated on product ${productId} → new priceId=${newPrice.id} $${amount}`);
  return newPrice.id;
}
  // ── GHL CONTACT UPSERT (tryout registration) ──────────────────
async function upsertGHLContact({ completedBy, name, address, city, state, zip, cell, email,
                                   playerName, age, dob, hw, pos1, pos2, tryoutDate }) {
  if (!process.env.GHL_API_KEY || !process.env.GHL_LOCATION_ID) {
    return { success: false, error: 'GHL env vars not set' };
  }
  const nameParts = (name || '').trim().split(' ');
  let formattedDob = '';
  if (dob) { const d = new Date(dob); if (!isNaN(d)) formattedDob = d.toISOString().split('T')[0]; }
  let formattedTryoutDate = '';
  if (tryoutDate) { const d = new Date(tryoutDate); if (!isNaN(d)) formattedTryoutDate = d.toISOString(); }

  try {
    const response = await axios.post(
      'https://services.leadconnectorhq.com/contacts/upsert',
      {
        locationId:  process.env.GHL_LOCATION_ID,
        firstName:   nameParts[0] || '',
        lastName:    nameParts.slice(1).join(' ') || '',
        email:       email   || '',
        phone:       cell    || '',
        address1:    address || '',
        city:        city    || '',
        state:       state   || '',
        postalCode:  zip     || '',
        dateOfBirth: formattedDob,
        tags: ['Baseball Tryout'],
        customFields: [
          { key: 'player_name',    value: playerName          || '' },
          { key: 'position_1',     value: pos1                || '' },
          { key: 'position_2',     value: pos2                || '' },
          { key: 'age',            value: age                 || '' },
          { key: 'completed_by',   value: completedBy         || '' },
          { key: 'tryout_date',    value: formattedTryoutDate      },
          { key: 'height__weight', value: hw                  || '' },
        ],
      },
      { headers: GHL_HEADERS() }
    );
    return { success: true, contactId: response.data?.contact?.id || '' };
  } catch (err) {
    const errMsg = err.response?.data ? JSON.stringify(err.response.data) : err.message;
    console.error('GHL contact upsert error:', errMsg);
    return { success: false, error: errMsg };
  }
}

// ── GHL PLAYER UPSERT ─────────────────────────────────────────
async function upsertGHLPlayer({
  name, email, cell, dob, bats, throws, hw,
  jersey, jersey2, gradYear, position, pos2,
  address, city, state, zip, highSchool,
  motherFirst, motherLast, motherCell, motherEmail,
  fatherFirst, fatherLast, fatherCell, fatherEmail,
  teamName,
}) {
  if (!process.env.GHL_API_KEY || !process.env.GHL_LOCATION_ID) return;
  try {
    await axios.post(
      'https://services.leadconnectorhq.com/contacts/upsert',
      {
        locationId: process.env.GHL_LOCATION_ID,
        // Contact main identity = Father
        firstName:  fatherFirst  || '',
        lastName:   fatherLast   || '',
        email:      fatherEmail  || '',
        phone:      fatherCell   || '',
        // Address = Player's address
        address1:   address      || '',
        city:       city         || '',
        state:      state        || '',
        postalCode: zip          || '',
        tags: ['Player'],
        customFields: [
          // Player info
          { key: 'players_name',      value: name         || '' },
          { key: 'player_dob',        value: dob          || '' },
          { key: 'player_email',      value: email        || '' },
          { key: 'player_cell',       value: cell         || '' },
          { key: 'bats',              value: bats         || '' },
          { key: 'throws',            value: throws       || '' },
          { key: 'jersey_number_1',   value: jersey       || '' },
          { key: 'jersey_number_2',   value: jersey2      || '' },
          { key: 'htwt',              value: hw           || '' },
          { key: 'grad_year',         value: gradYear     || '' },
          { key: 'high_school',       value: highSchool   || '' },
          { key: 'player_address',    value: address      || '' },
          { key: 'position1',         value: position     || '' },
          { key: 'position2',         value: pos2         || '' },
          { key: 'team_name',         value: teamName     || '' },
          // Mother info
          { key: 'mother_first_name', value: motherFirst  || '' },
          { key: 'mother_last_name',  value: motherLast   || '' },
          { key: 'mother_cell',       value: motherCell   || '' },
          { key: 'mother_email',      value: motherEmail  || '' },
        ],
      },
      { headers: GHL_HEADERS() }
    );
    console.log(`✅  GHL player upserted: ${fatherFirst} ${fatherLast} (${fatherEmail})`);
  } catch (err) {
    console.error('GHL player upsert error:', err.response?.data ? JSON.stringify(err.response.data) : err.message);
  }
}

// ── GHL COACH UPSERT ──────────────────────────────────────────
async function upsertGHLCoach({ firstName, lastName, email, phone, teamName, state, city, ageGroup, bio }) {
  if (!process.env.GHL_API_KEY || !process.env.GHL_LOCATION_ID) return;
  try {
    await axios.post(
      'https://services.leadconnectorhq.com/contacts/upsert',
      {
        locationId: process.env.GHL_LOCATION_ID,
        firstName:  firstName || '',
        lastName:   lastName  || '',
        email:      email     || '',
        phone:      phone     || '',
        city:       city      || '',
        state:      state     || '',
        tags:       ['Head Coach Name'],
        customFields: [
          { key: 'team_name',  value: teamName  || '' },
          { key: 'age_group',  value: ageGroup  || '' },
          { key: 'bio',        value: bio       || '' },
        ],
      },
      { headers: GHL_HEADERS() }
    );
  } catch (err) {
    console.error('GHL coach upsert error:', err.response?.data ? JSON.stringify(err.response.data) : err.message);
  }
}

// ════════════════════════════════════════════════════════════════
//  AUTH HELPERS
// ════════════════════════════════════════════════════════════════

const signToken = id => jwt.sign({ coachId: id }, process.env.JWT_SECRET, { expiresIn: '7d' });

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ message: 'No token provided' });
  try {
    const { coachId } = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET);
    req.coachId = coachId;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ message: 'No token' });
  try {
    const payload = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET);
    if (payload.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}

// ════════════════════════════════════════════════════════════════
//  NORMALIZERS
// ════════════════════════════════════════════════════════════════

function normalizeCoach(c) {
  return {
    _id:         c._id,
    firstName:   c.first_name   || '',
    lastName:    c.last_name    || '',
    emailPublic: c.email_public || '',
    phonePublic: c.phone_public || '',
    bio:         c.bio          || '',
    image:       c.image_url    || '',
    teamName:    c.team_name    || '',
    state:       c.state        || '',
    location:    c.location     || '',
    ageGroup:    c.age_group    || '',
    teamDetails:    c.team_details     || '',
    registerEnabled: c.register_enabled !== false,
    assistant1:  c.assistant1   || {},
    assistant2:  c.assistant2   || {},
  };
}

function normalizeTryout(t) {
  return {
    _id:             t._id,
    date:            t.date             || '',
    time:            t.time             || '',
    location:        t.location         || '',
    fee:             t.fee              || 'Free',
    city:            t.city             || '',
    state:           t.state            || '',
    stripeProductId: t.stripe_product_id || '',
    stripePriceId:   t.stripe_price_id   || '',
  };
}

function normalizePlayer(p) {
  return {
    _id:          p._id,
    name:         p.name         || '',
    jersey:       p.jersey       || '',
    jersey2:      p.jersey_2     || '',
    gradYear:     p.grad_year    || '',
    position:     p.position     || '',
    pos2:         p.pos2         || '',
    hw:           p.hw           || '',
    city:         p.city         || '',
    state:        p.state        || '',
    address:      p.address      || '',
    zip:          p.zip          || '',
    email:        p.email        || '',
    cell:         p.cell         || '',
    dob:          p.dob          || '',
    bats:         p.bats         || '',
    throws:       p.throws       || '',
    highSchool:   p.high_school  || '',
    motherFirst:  p.mother_first || '',
    motherLast:   p.mother_last  || '',
    motherCell:   p.mother_cell  || '',
    motherEmail:  p.mother_email || '',
    fatherFirst:  p.father_first || '',
    fatherLast:   p.father_last  || '',
    fatherCell:   p.father_cell  || '',
    fatherEmail:  p.father_email || '',
  };
}

function normalizeGame(g) {
  return {
    _id:       g._id,
    startDate: g.start_date || '',
    endDate:   g.end_date   || '',
    event:     g.event      || '',
    city:      g.city       || '',
    state:     g.state      || '',
    result:    g.result     || 'Upcoming',
  };
}

// ════════════════════════════════════════════════════════════════
//  TEMP: GET GHL CUSTOM FIELDS
// ════════════════════════════════════════════════════════════════
app.get('/api/ghl-fields', async (req, res) => {
  try {
    const response = await axios.get(
      `https://services.leadconnectorhq.com/contacts/custom-fields?locationId=${process.env.GHL_LOCATION_ID}`,
      { headers: GHL_HEADERS() }
    );
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// ════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════════════════

// POST /api/coach/register
app.post('/api/coach/register', async (req, res) => {
  try {
    const { firstName, lastName, email, phone, teamName, state, ageGroup, password } = req.body;
    if (!firstName || !lastName || !email || !phone || !teamName || !password)
      return res.status(400).json({ message: 'All fields are required' });
    if (password.length < 8)
      return res.status(400).json({ message: 'Password must be at least 8 characters' });

    const existing = await Coach.findOne({ email: email.toLowerCase().trim() });
    if (existing) return res.status(409).json({ message: 'An account with this email already exists' });

    const hashed = await bcrypt.hash(password, 12);
    await Coach.create({
      first_name:   firstName,
      last_name:    lastName,
      email:        email.toLowerCase().trim(),
      phone,
      team_name:    teamName,
      state:        state ? state.toUpperCase() : '',
      age_group:    ageGroup || '',
      password:     hashed,
      email_public: email.toLowerCase().trim(),
      phone_public: phone,
    });

    await upsertGHLCoach({ firstName, lastName, email, phone, teamName });
    res.status(201).json({ message: 'Account created successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// POST /api/coach/login
app.post('/api/coach/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: 'Email and password are required' });

    const coach = await Coach.findOne({ email: email.toLowerCase().trim() });
    if (!coach) return res.status(401).json({ message: 'Invalid email or password' });
    if (!(await bcrypt.compare(password, coach.password)))
      return res.status(401).json({ message: 'Invalid email or password' });

    res.json({
      token: signToken(coach._id),
      coach: { _id: coach._id, firstName: coach.first_name, lastName: coach.last_name, teamName: coach.team_name }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/coach/forgot-password
app.post('/api/coach/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const coach = await Coach.findOne({ email: email.toLowerCase().trim() });
    if (!coach) return res.json({ message: 'If that email exists, a 6-digit code has been sent.' });

    const otp    = generateOTP();
    const expiry = new Date(Date.now() + 10 * 60 * 1000);

    await Coach.findByIdAndUpdate(coach._id, {
      otp_code:    otp,
      otp_expiry:  expiry,
      otp_purpose: 'reset',
    });

    await sendOTPEmail(coach.email, otp, 'reset');

    res.json({
      message: 'If that email exists, a 6-digit code has been sent.',
      ...((!process.env.EMAIL_USER) && { devOtp: otp }),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/coach/verify-otp-reset
app.post('/api/coach/verify-otp-reset', async (req, res) => {
  try {
    const { email, otp, password } = req.body;
    if (!email || !otp || !password)
      return res.status(400).json({ message: 'Email, OTP, and new password are required' });
    if (password.length < 8)
      return res.status(400).json({ message: 'Password must be at least 8 characters' });

    const coach = await Coach.findOne({ email: email.toLowerCase().trim() });
    if (!coach || coach.otp_purpose !== 'reset' || coach.otp_code !== otp || new Date() > coach.otp_expiry)
      return res.status(400).json({ message: 'OTP is invalid or has expired' });

    const hashed = await bcrypt.hash(password, 12);
    await Coach.findByIdAndUpdate(coach._id, {
      password:    hashed,
      otp_code:    null,
      otp_expiry:  null,
      otp_purpose: null,
    });

    res.json({ message: 'Password updated successfully. You can now log in.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ════════════════════════════════════════════════════════════════
//  COACH DASHBOARD ROUTES (protected)
// ════════════════════════════════════════════════════════════════

// GET /api/coach/me
app.get('/api/coach/me', requireAuth, async (req, res) => {
  try {
    const coach = await Coach.findById(req.coachId).select('-password');
    if (!coach) return res.status(404).json({ message: 'Coach not found' });
    res.json({ coach: normalizeCoach(coach) });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// PUT /api/coach/update-profile
app.put('/api/coach/update-profile', requireAuth, async (req, res) => {
  try {
    const map = {
      firstName:   'first_name',
      lastName:    'last_name',
      emailPublic: 'email_public',
      phonePublic: 'phone_public',
      bio:         'bio',
      imageUrl:    'image_url',
      teamName:    'team_name',
      state:       'state',
      location:    'location',
      ageGroup:    'age_group',
      teamDetails: 'team_details',
      registerEnabled: 'register_enabled',
    };
    const update = {};
    Object.entries(map).forEach(([jsKey, dbKey]) => {
      if (req.body[jsKey] !== undefined) update[dbKey] = req.body[jsKey];
    });
    if (update.state) update.state = update.state.toUpperCase();

    const coach = await Coach.findByIdAndUpdate(req.coachId, update, { new: true }).select('-password');
    if (!coach) return res.status(404).json({ message: 'Coach not found' });

    await upsertGHLCoach({
      firstName: coach.first_name,
      lastName:  coach.last_name,
      email:     coach.email_public,
      phone:     coach.phone_public,
      teamName:  coach.team_name,
      state:     coach.state,
      city:      coach.location,
      ageGroup:  coach.age_group,
      bio:       coach.bio,
    });

    res.json({ message: 'Saved', coach: normalizeCoach(coach) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// PUT /api/coach/update-assistants
app.put('/api/coach/update-assistants', requireAuth, async (req, res) => {
  try {
    const update = {};
    if (req.body.assistant1 !== undefined) update.assistant1 = req.body.assistant1;
    if (req.body.assistant2 !== undefined) update.assistant2 = req.body.assistant2;

    const coach = await Coach.findByIdAndUpdate(req.coachId, update, { new: true }).select('-password');
    if (!coach) return res.status(404).json({ message: 'Coach not found' });
    res.json({ message: 'Saved', coach: normalizeCoach(coach) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// POST /api/coach/upload-image
app.post('/api/coach/upload-image', requireAuth, async (req, res) => {
  try {
    const { base64, fileName, mimeType, saveToProfile, slot } = req.body;
    if (!base64 || !fileName) return res.status(400).json({ message: 'base64 and fileName required' });

    const imageUrl = await uploadImageToGHL(base64, fileName, mimeType);

    if (saveToProfile || slot === 'head') {
      await Coach.findByIdAndUpdate(req.coachId, { image_url: imageUrl });
    }

    if (slot === 'asst1' || slot === 'asst2') {
      const col   = slot === 'asst1' ? 'assistant1' : 'assistant2';
      const coach = await Coach.findById(req.coachId);
      if (coach) {
        const updated = { ...(coach[col] || {}), image: imageUrl };
        await Coach.findByIdAndUpdate(req.coachId, { [col]: updated });
      }
    }

    res.json({ message: 'Uploaded', imageUrl });
  } catch (err) {
    console.error('GHL upload error:', err.message);
    res.status(500).json({ message: err.message || 'Upload failed' });
  }
});

// DELETE /api/coach/delete-image
app.delete('/api/coach/delete-image', requireAuth, async (req, res) => {
  try {
    const { slot } = req.body;
    if (!slot) return res.status(400).json({ message: 'slot required' });

    if (slot === 'head') {
      await Coach.findByIdAndUpdate(req.coachId, { image_url: '' });
    } else {
      const col   = slot === 'asst1' ? 'assistant1' : 'assistant2';
      const coach = await Coach.findById(req.coachId);
      if (coach && coach[col]) {
        const updated = { ...coach[col], image: '' };
        await Coach.findByIdAndUpdate(req.coachId, { [col]: updated });
      }
    }
    res.json({ message: 'Image reference removed' });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Delete failed' });
  }
});

// ── TRYOUT ROUTES ─────────────────────────────────────────────

app.get('/api/coach/tryouts', requireAuth, async (req, res) => {
  try {
    const tryouts = await Tryout.find({ coach_id: req.coachId }).sort({ created_at: 1 });
    res.json({ tryouts: tryouts.map(normalizeTryout) });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/coach/tryouts', requireAuth, async (req, res) => {
  try {
    const { date, time, location, fee, city, state } = req.body;
    if (!date || !time || !location || !fee)
      return res.status(400).json({ message: 'date, time, location and fee are all required' });
    const tryout = await Tryout.create({
      coach_id: req.coachId, date, time, location, fee,
      city: city || '', state: state || '',
    });

    // ── Stripe product creation for paid tryouts ──────────────
    const feeAmount = parseFloat((fee || '').replace('$', ''));
    if (stripe && !isNaN(feeAmount) && feeAmount > 0) {
      try {
        const coach      = await Coach.findById(req.coachId).select('team_name');
        const teamLabel  = coach?.team_name || 'Team';
        const productName = `${teamLabel} - ${location} - ${date}`;
        const product = await stripe.products.create({ name: productName });
        const price   = await stripe.prices.create({
          product:     product.id,
          unit_amount: Math.round(feeAmount * 100),
          currency:    'usd',
        });
        await Tryout.findByIdAndUpdate(tryout._id, {
          stripe_product_id: product.id,
          stripe_price_id:   price.id,
        });
        tryout.stripe_product_id = product.id;
        tryout.stripe_price_id   = price.id;
        console.log(`📦  Stripe tryout product created: "${productName}" → ${product.id} / ${price.id}`);
      } catch (stripeErr) {
        console.error('⚠️  Stripe tryout product creation failed:', stripeErr.message);
      }
    }

    res.status(201).json({ message: 'Tryout added', tryout: normalizeTryout(tryout) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

app.put('/api/coach/tryouts/:tryoutId', requireAuth, async (req, res) => {
  try {
    const { date, time, location, fee, city, state } = req.body;
    if (!date || !time || !location)
      return res.status(400).json({ message: 'date, time and location are required' });

    const existing = await Tryout.findOne({ _id: req.params.tryoutId, coach_id: req.coachId });
    if (!existing) return res.status(404).json({ message: 'Tryout not found' });

    const newFee     = fee || 'Free';
    const feeAmount  = parseFloat((newFee).replace('$', ''));
    const isFree     = isNaN(feeAmount) || feeAmount <= 0;

    // Fields that affect the Stripe product name
    const nameChanged = existing.location !== location || existing.date !== date;
    const oldFeeAmt   = parseFloat((existing.fee || '').replace('$', ''));
    const feeChanged  = oldFeeAmt !== feeAmount;

    let stripeProductId = existing.stripe_product_id || '';
    let stripePriceId   = existing.stripe_price_id   || '';

    if (stripe) {
      try {
        if (isFree) {
          // Fee removed — archive existing product if any
          if (stripeProductId) {
            await deleteStripeProduct(stripeProductId);
            console.log(`🗑️  Tryout fee removed — archived product ${stripeProductId}`);
          }
          stripeProductId = '';
          stripePriceId   = '';

        } else if (!stripeProductId) {
          // No product yet (legacy record or missed on create) — create fresh
          const coach      = await Coach.findById(req.coachId).select('team_name');
          const teamLabel  = coach?.team_name || 'Team';
          const productName = `${teamLabel} - ${location} - ${date}`;
          const product = await stripe.products.create({ name: productName });
          const price   = await stripe.prices.create({
            product:     product.id,
            unit_amount: Math.round(feeAmount * 100),
            currency:    'usd',
          });
          stripeProductId = product.id;
          stripePriceId   = price.id;
          console.log(`📦  Stripe tryout product created (edit): "${productName}" → ${product.id} / ${price.id}`);

        } else {
          // Product exists — update name if location/date changed
          if (nameChanged) {
            const coach      = await Coach.findById(req.coachId).select('team_name');
            const teamLabel  = coach?.team_name || 'Team';
            const productName = `${teamLabel} - ${location} - ${date}`;
            await stripe.products.update(stripeProductId, { name: productName });
            console.log(`✏️  Stripe tryout product renamed: "${productName}"`);
          }

          // Update price if fee changed — deactivate old, create new
          if (feeChanged) {
            if (stripePriceId) {
              await stripe.prices.update(stripePriceId, { active: false });
              console.log(`🗑️  Old Stripe price deactivated: ${stripePriceId}`);
            }
            const price = await stripe.prices.create({
              product:     stripeProductId,
              unit_amount: Math.round(feeAmount * 100),
              currency:    'usd',
            });
            stripePriceId = price.id;
            console.log(`💰  New Stripe price created: ${price.id} ($${feeAmount})`);
          }
        }
      } catch (stripeErr) {
        console.error('⚠️  Stripe tryout product sync failed:', stripeErr.message);
      }
    }

    const tryout = await Tryout.findOneAndUpdate(
      { _id: req.params.tryoutId, coach_id: req.coachId },
      {
        date, time, location,
        fee:               newFee,
        city:              city  || '',
        state:             state || '',
        stripe_product_id: stripeProductId,
        stripe_price_id:   stripePriceId,
      },
      { new: true }
    );

    res.json({ message: 'Tryout updated', tryout: normalizeTryout(tryout) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

app.delete('/api/coach/tryouts/:tryoutId', requireAuth, async (req, res) => {
  try {
    await Tryout.findOneAndDelete({ _id: req.params.tryoutId, coach_id: req.coachId });
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

app.get('/api/coach/tryout-registrations', requireAuth, async (req, res) => {
  try {
    const data = await TryoutRegistration.find({ coach_id: req.coachId }).sort({ created_at: -1 });
    res.json({ registrations: data });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── SCHEDULE ROUTES ───────────────────────────────────────────

app.get('/api/coach/schedule', requireAuth, async (req, res) => {
  try {
    const data = await Schedule.find({ coach_id: req.coachId }).sort({ date_sort: 1 });
    res.json({ schedule: data.map(normalizeGame) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/coach/schedule', requireAuth, async (req, res) => {
  try {
    const { startDate, endDate, event, city, state } = req.body;
    if (!startDate || !endDate || !event)
      return res.status(400).json({ message: 'Start date, end date, and event are required' });
    const game = await Schedule.create({
      coach_id:   req.coachId,
      date:       startDate,
      start_date: startDate,
      end_date:   endDate,
      event,
      city:       city  || '',
      state:      state || '',
      date_sort:  startDate,
    });
    res.status(201).json({ message: 'Game added', game: normalizeGame(game) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/coach/schedule/:gameId', requireAuth, async (req, res) => {
  try {
    const { startDate, endDate, event, city, state } = req.body;
    if (!startDate || !endDate || !event)
      return res.status(400).json({ message: 'Start date, end date, and event are required' });
    const game = await Schedule.findOneAndUpdate(
      { _id: req.params.gameId, coach_id: req.coachId },
      { date: startDate, start_date: startDate, end_date: endDate, event, city: city || '', state: state || '', date_sort: startDate },
      { new: true }
    );
    if (!game) return res.status(404).json({ message: 'Game not found' });
    res.json({ message: 'Game updated', game: normalizeGame(game) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/coach/schedule/:gameId', requireAuth, async (req, res) => {
  try {
    await Schedule.findOneAndDelete({ _id: req.params.gameId, coach_id: req.coachId });
    res.json({ message: 'Game deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── FINANCIALS ROUTES ─────────────────────────────────────────

app.get('/api/coach/financials', requireAuth, async (req, res) => {
  try {
    const data = await TeamFinancials.findOne({ coach_id: req.coachId });
    res.json({ financials: data || null });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/coach/financials
// Creates or updates financial settings and syncs Stripe products/prices directly.
//
// Rules:
//   • Deposit OFF, Monthly OFF  → Full Payment product only
//   • Deposit ON,  Monthly OFF  → Deposit + Remaining Balance products (no Full Payment)
//   • Deposit OFF, Monthly ON   → Monthly Installment product only (no Full, no Remainder)
//   • Deposit ON,  Monthly ON   → Deposit + Monthly Installment products only (NO Remainder — balance collected via installments)
//   • Fee change   → archive all old Stripe products and recreate fresh
//   • Toggle OFF   → archive that product, clear stored IDs
//   • Stripe error → logs error but always saves to MongoDB
app.post('/api/coach/financials', requireAuth, async (req, res) => {
  try {
    const {
      playerFee,
      paymentDeadline,
      fullPayOnly,
      depositEnabled,
      depositAmount,
      monthlyPayments,
      installmentMonths,
    } = req.body;

    // ── Fetch coach team name for Stripe product labels ───────
    const coach = await Coach.findById(req.coachId).select('team_name');
    const teamLabel = coach?.team_name || 'Team';

    // ── Fetch existing record ─────────────────────────────────
    const existing = await TeamFinancials.findOne({ coach_id: req.coachId });

    // ── Dollar amounts ────────────────────────────────────────
    const fee         = Number(playerFee)         || 0;
    const deposit     = Number(depositAmount)     || 250;
    const months      = Number(installmentMonths) || 3;
    const remainder   = Math.max(0, fee - deposit);
    const installment = months > 0
      ? Math.round((fee / months) * 100) / 100
      : fee;

    // ── Did the player fee or deposit amount change since last save? ──
    const feeChanged     = !!existing && existing.player_fee     !== fee;
    const depositChanged = !!existing && existing.deposit_amount !== deposit;

    // ── Build the MongoDB update object ──────────────────────
    const update = {
      coach_id:           req.coachId,
      player_fee:         fee,
      payment_deadline:   paymentDeadline || '',
      full_pay_only:      fullPayOnly !== false,
      deposit_enabled:    !!depositEnabled,
      deposit_amount:     deposit,
      monthly_payments:   !!monthlyPayments,
      installment_months: months,
    };

    // ── Stripe product/price sync ─────────────────────────────
    try {
      // carry() returns the stored Stripe ID if fee is unchanged, '' if fee changed
      const carry = (field) => feeChanged ? '' : (existing?.[field] || '');

      update.stripe_product_full        = carry('stripe_product_full');
      update.stripe_price_full          = carry('stripe_price_full');
      update.stripe_product_deposit     = carry('stripe_product_deposit');
      update.stripe_price_deposit       = carry('stripe_price_deposit');
      update.stripe_product_remainder   = carry('stripe_product_remainder');
      update.stripe_price_remainder     = carry('stripe_price_remainder');
      update.stripe_product_installment = carry('stripe_product_installment');
      update.stripe_price_installment   = carry('stripe_price_installment');

      // If fee or deposit changed — update prices on affected products only
      if ((feeChanged || depositChanged) && existing) {
        console.log('💱  Fee/deposit changed — updating prices on affected Stripe products...');

        // Full pay — update only if fee changed and deposit is still OFF
        if (feeChanged && existing.stripe_product_full && !depositEnabled) {
          const newPriceId = await updateStripeProductPrice(existing.stripe_product_full, fee);
          update.stripe_product_full = existing.stripe_product_full;
          update.stripe_price_full   = newPriceId;
        }

        // Deposit — update only if deposit amount changed and deposit is still ON
        if (depositChanged && existing.stripe_product_deposit && depositEnabled && deposit > 0) {
          const newPriceId = await updateStripeProductPrice(existing.stripe_product_deposit, deposit);
          update.stripe_product_deposit = existing.stripe_product_deposit;
          update.stripe_price_deposit   = newPriceId;
        }

        // Remainder — update if fee OR deposit changed (remainder = fee - deposit)
        if ((feeChanged || depositChanged) && existing.stripe_product_remainder && depositEnabled && remainder > 0 && !monthlyPayments) {
          const newPriceId = await updateStripeProductPrice(existing.stripe_product_remainder, remainder);
          update.stripe_product_remainder = existing.stripe_product_remainder;
          update.stripe_price_remainder   = newPriceId;
        }

        // Installment — deactivate old prices only if fee changed (installment is based on fee)
        if (feeChanged && existing.stripe_product_installment && monthlyPayments) {
          const prices = await stripe.prices.list({ product: existing.stripe_product_installment, active: true, limit: 100 });
          await Promise.all(prices.data.map(p => stripe.prices.update(p.id, { active: false })));
          update.stripe_product_installment = existing.stripe_product_installment;
          update.stripe_price_installment   = '';
        }
      }

      // ── Full pay product (ONLY when deposit is OFF) ───────────────────────────
      if (!depositEnabled) {
        if (fee > 0 && !update.stripe_product_full) {
          // No existing product (new setup or deposit just turned OFF) — create fresh
          const { productId, priceId } = await createStripeProductWithPrice(
            `${teamLabel} – Full Payment ($${fee})`, fee
          );
          update.stripe_product_full = productId;
          update.stripe_price_full   = priceId;
        }
      } else {
        // Deposit turned ON — full pay product no longer needed, archive it
        if (existing?.stripe_product_full) {
          await deleteStripeProduct(existing.stripe_product_full);
        }
        update.stripe_product_full = '';
        update.stripe_price_full   = '';
      }

      // ── Deposit product (ONLY when deposit is ON) ─────────────────────────────
      if (depositEnabled && deposit > 0) {
        if (!update.stripe_product_deposit) {
          // No existing product (new setup or deposit just turned ON) — create fresh
          const { productId, priceId } = await createStripeProductWithPrice(
            `${teamLabel} – Deposit ($${deposit})`, deposit
          );
          update.stripe_product_deposit = productId;
          update.stripe_price_deposit   = priceId;
        }
      } else {
        // Deposit turned OFF — archive deposit product
        if (existing?.stripe_product_deposit) {
          await deleteStripeProduct(existing.stripe_product_deposit);
        }
        update.stripe_product_deposit = '';
        update.stripe_price_deposit   = '';
      }

      // ── Remainder product (deposit ON + monthly OFF only) ─────────────────────
      if (depositEnabled && remainder > 0 && !monthlyPayments) {
        if (!update.stripe_product_remainder) {
          // No existing product — create fresh
          const { productId, priceId } = await createStripeProductWithPrice(
            `${teamLabel} – Remaining Balance ($${remainder})`, remainder
          );
          update.stripe_product_remainder = productId;
          update.stripe_price_remainder   = priceId;
        }
      } else {
        // Conditions no longer met — archive remainder product
        if (existing?.stripe_product_remainder) {
          await deleteStripeProduct(existing.stripe_product_remainder);
        }
        update.stripe_product_remainder = '';
        update.stripe_price_remainder   = '';
      }

      // ── Monthly installment product ───────────────────────────────────────────
      // ONE product created as container. Prices created per-player at checkout.
      if (monthlyPayments) {
        if (!update.stripe_product_installment) {
          // No existing product — create fresh
          const product = await stripe.products.create({
            name: `${teamLabel} – Monthly Installment`,
            metadata: { coachId: String(req.coachId), teamLabel },
          });
          update.stripe_product_installment = product.id;
          update.stripe_price_installment   = '';
          console.log(`📦  Stripe installment product created: ${product.id}`);
        }
      } else {
        // Monthly turned OFF — archive installment product
        if (existing?.stripe_product_installment) {
          await deleteStripeProduct(existing.stripe_product_installment);
        }
        update.stripe_product_installment = '';
        update.stripe_price_installment   = '';
      }

    } catch (stripeErr) {
      console.error('⚠️  Stripe product sync error:', stripeErr.message);
      return res.status(500).json({ message: 'Payment setup failed: ' + stripeErr.message });
    }

    // ── Persist to MongoDB ────────────────────────────────────
    const data = await TeamFinancials.findOneAndUpdate(
      { coach_id: req.coachId },
      update,
      { upsert: true, new: true }
    );

    res.json({ message: 'Saved', financials: data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err.message });
  }
});

// ── STRIPE CHECKOUT ───────────────────────────────────────────
// POST /api/checkout
// Body: { coachId, paymentType, playerPaymentId, successUrl, cancelUrl }
// paymentType: 'full' | 'deposit' | 'remainder' | 'installment'

/**
 * Returns the number of whole calendar months from today up to and including
 * the deadline month, accounting for the day the player registered (charge day).
 *
 * chargeDay = day of month the player registered (Stripe bills on this day each month).
 * If the charge day in the deadline month falls AFTER the deadline date, that month's
 * charge will never fire before cancel_at kicks in — so we exclude it.
 *
 * Example: registered April 16, deadline October 15
 *   → October charge fires Oct 16, which is after Oct 15 deadline → excluded
 *   → 6 months counted (Apr, May, Jun, Jul, Aug, Sep)
 *
 * Always returns at least 1.
 */
function monthsRemainingUntilDeadline(deadlineStr, chargeDay) {
  if (!deadlineStr) return 1;
  const now      = new Date();
  const deadline = new Date(deadlineStr);
  if (isNaN(deadline)) return 1;

  const nowMonth      = now.getFullYear() * 12 + now.getMonth();
  const deadlineMonth = deadline.getFullYear() * 12 + deadline.getMonth();

  let months = deadlineMonth - nowMonth + 1;

  // If Stripe would charge later in the month than the deadline date,
  // that last charge is blocked by cancel_at — do not count it
  const day = chargeDay || now.getDate();
  if (day > deadline.getDate()) {
    months = months - 1;
  }

  return Math.max(1, months);
}

// GET /api/teams/:id/installment-preview
// Public — returns the dynamic per-month amount for a player registering today.
// Used by team.html to show the correct payment plan before checkout.
app.get('/api/teams/:id/installment-preview', async (req, res) => {
  try {
    const financials = await TeamFinancials.findOne({ coach_id: req.params.id });
    if (!financials || !financials.monthly_payments) {
      return res.json({ enabled: false });
    }

    const fee        = financials.player_fee     || 0;
    const deposit    = financials.deposit_amount || 0;
    const depEnabled = financials.deposit_enabled || false;
    const balance    = depEnabled ? Math.max(0, fee - deposit) : fee;
    const chargeDay  = new Date().getDate();
    const months     = monthsRemainingUntilDeadline(financials.payment_deadline, chargeDay);
    const perMonth   = months > 0 ? Math.ceil((balance / months) * 100) / 100 : balance;

    res.json({
      enabled:         true,
      months,
      perMonth,
      balance,
      totalFee:        fee,
      depositEnabled:  depEnabled,
      depositAmount:   deposit,
      paymentDeadline: financials.payment_deadline || '',
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── COUPON CODES ──────────────────────────────────────────────
// Coupon codes are created by the Stripe account owner in the Stripe
// Dashboard (Products → Coupons → create coupon + promotion code) and are
// account-level, so one code works across ALL coaches' products/prices.
// Players enter the code directly on Stripe's hosted checkout page — every
// session below is created with `allow_promotion_codes: true`.

app.post('/api/checkout', async (req, res) => {
  if (!stripe) return res.status(500).json({ message: 'Stripe is not configured on the server' });

  try {
    const { coachId, paymentType, playerPaymentId, pendingId, successUrl, cancelUrl } = req.body;
    if (!coachId || !paymentType) {
      return res.status(400).json({ message: 'coachId and paymentType are required' });
    }
    if (!playerPaymentId && !pendingId) {
      return res.status(400).json({ message: 'Either playerPaymentId or pendingId is required' });
    }

    // If a pendingId was passed, verify it exists and belongs to this coach.
    if (pendingId) {
      const pending = await PendingRegistration.findById(pendingId).lean();
      if (!pending) {
        return res.status(404).json({ message: 'Pending registration not found or expired. Please resubmit the form.' });
      }
      if (String(pending.coach_id) !== String(coachId)) {
        return res.status(403).json({ message: 'Pending registration does not belong to this team.' });
      }
    }

    // ── Get stored Stripe price IDs from financials ───────────
    const financials = await TeamFinancials.findOne({ coach_id: coachId });
    if (!financials) return res.status(404).json({ message: 'Team financials not found' });

    const coach = await Coach.findById(coachId).select('team_name');
    const teamLabel = coach?.team_name || 'Team';

    // ── Build checkout session ────────────────────────────────
    let lineItems;
    let mode;

    if (paymentType === 'installment') {
      // ── DYNAMIC installment: calculate months remaining for this player ──
      if (!financials.monthly_payments) {
        return res.status(400).json({ message: 'Monthly payments are not enabled for this team.' });
      }

      const productId = financials.stripe_product_installment;
      if (!productId) {
        return res.status(404).json({
          message: 'No installment product found. Please re-save your financial setup.',
        });
      }

      if (!financials.payment_deadline) {
        return res.status(400).json({ message: 'No payment deadline set. Coach must set a deadline first.' });
      }

      const fee          = financials.player_fee      || 0;
      const deposit      = financials.deposit_amount  || 0;
      const depEnabled   = financials.deposit_enabled || false;

      // Balance to split = full fee, or fee minus deposit if deposit is enabled
      const balanceToSplit = depEnabled ? Math.max(0, fee - deposit) : fee;
      if (balanceToSplit <= 0) {
        return res.status(400).json({ message: 'No balance remaining to split into installments.' });
      }

      const chargeDay     = new Date().getDate();
      const months        = monthsRemainingUntilDeadline(financials.payment_deadline, chargeDay);
      // Industry-standard first-payment adjustment:
      // Base amount = floor(total / months), remainder goes on month 1.
      // e.g. $1000 / 3 = $333.33 base, $0.01 remainder
      //   Month 1 → $333.34, Month 2-3 → $333.33, Total = $1000.00 exactly.
      // The first payment is handled by checkout.session.completed which already
      // records amountPaid from session.amount_total — so the correct amount is
      // always captured regardless of which month it is.
      const baseMonthCents      = Math.floor((balanceToSplit / months) * 100);
      const remainderCents      = Math.round(balanceToSplit * 100) - (baseMonthCents * months);
      const firstMonthCents     = baseMonthCents + remainderCents; // month 1 absorbs remainder
      const perMonthCents       = baseMonthCents;                  // months 2-N use base amount

      console.log(`📅  Installment checkout — deadline=${financials.payment_deadline} months=${months} balance=$${balanceToSplit} per-month=$${(perMonthCents/100).toFixed(2)}`);

      // ── Find existing price for this exact amount AND month count ──────
      // We match on BOTH unit_amount AND months metadata to avoid reusing a
      // price from a previous deadline/registration that happens to have the
      // same dollar amount but a different number of installments.
      // e.g. $500/mo over 2 months vs $500/mo over 4 months are different plans
      // even though the Stripe price amount is identical.
      const existingPrices = await stripe.prices.list({
        product: productId,
        active:  true,
        limit:   100,
      });

      // Find or create the BASE recurring price (months 2-N)
      let installmentPrice = existingPrices.data.find(p =>
        p.unit_amount === perMonthCents &&
        p.metadata?.months === String(months) &&
        p.metadata?.paymentDeadline === financials.payment_deadline
      );

      if (installmentPrice) {
        console.log(`♻️  Reusing existing Stripe price ${installmentPrice.id} (${perMonthCents/100}/mo × ${months} months)`);
      } else {
        installmentPrice = await stripe.prices.create({
          product:     productId,
          unit_amount: perMonthCents,
          currency:    'usd',
          recurring:   { interval: 'month', interval_count: 1 },
          metadata:    {
            months:          String(months),
            paymentDeadline: financials.payment_deadline,
            balanceToSplit:  String(balanceToSplit),
          },
        });
        console.log(`💰  New Stripe price created ${installmentPrice.id} (${perMonthCents/100}/mo × ${months} months)`);
      }

      // If there is a remainder, add a one-time invoice item for the extra cents.
      // Stripe will merge it into the first invoice automatically so the player
      // sees a single charge of (base + remainder) on month 1.
      if (remainderCents > 0) {
        // We need the customer ID — look it up after session creation via webhook.
        // Store remainderCents in session metadata so the webhook can add it.
        console.log(`🪙  Remainder ${remainderCents} cents will be added to first invoice`);
      }

      // ── cancel_at = deadline date (Stripe auto-cancels the subscription) ──
      const cancelAtTimestamp = Math.floor(new Date(financials.payment_deadline) / 1000);

      mode      = 'subscription';
      lineItems = [{ price: installmentPrice.id, quantity: 1 }];

      // Store for use in session metadata below
      req._installmentTotalMonths    = months;
      req._installmentRemainderCents = remainderCents;

      // Store cancel_at for use in session creation below
      req._installmentCancelAt = cancelAtTimestamp;

      console.log(`📅  Installment plan — months=${months} base=${perMonthCents/100} remainder=${remainderCents}cents first=${firstMonthCents/100}`);

    } else {
      // ── Static payment types: full | deposit | remainder ──────
      const priceIdMap = {
        full:      financials.stripe_price_full,
        deposit:   financials.stripe_price_deposit,
        remainder: financials.stripe_price_remainder,
      };

      const priceId = priceIdMap[paymentType];
      if (!priceId) {
        return res.status(404).json({
          message: `No Stripe price found for paymentType "${paymentType}". Please re-save your financial setup to generate Stripe products.`,
        });
      }

      // Verify the price is still active in Stripe
      let price;
      try {
        price = await stripe.prices.retrieve(priceId);
      } catch (err) {
        return res.status(404).json({ message: `Stripe price ${priceId} not found: ${err.message}` });
      }

      if (!price.active) {
        return res.status(400).json({
          message: `Stripe price ${priceId} is inactive. Please re-save your financial setup to regenerate Stripe products.`,
        });
      }

      mode      = 'payment';
      lineItems = [{ price: priceId, quantity: 1 }];
    }

    // ── Create checkout session ───────────────────────────────
    const sessionParams = {
      mode,
      line_items: lineItems,
      success_url: successUrl || `${req.headers.origin || 'https://yoursite.com'}?payment=success`,
      cancel_url:  cancelUrl  || `${req.headers.origin || 'https://yoursite.com'}?payment=cancelled`,
      // Shows Stripe's built-in "Add promotion code" field on the hosted
      // checkout page — coupons are created by the account owner in the
      // Stripe Dashboard and apply across all coaches/products automatically.
      allow_promotion_codes: true,
      metadata: {
        // One of these will be set; the webhook handles both cases.
        ...(playerPaymentId ? { playerPaymentId } : {}),
        ...(pendingId       ? { pendingId       } : {}),
        paymentType,
        coachId,
        ...(paymentType === 'installment' ? {
          paymentDeadline: financials.payment_deadline || '',
          totalMonths:     String(req._installmentTotalMonths || 0),
          remainderCents:  String(req._installmentRemainderCents || 0),
        } : {}),
      },
    };

    // For installments: store ids on the subscription itself
    // so the customer.subscription.deleted webhook can link back to the player.
    // When pendingId is used, the webhook backfills playerPaymentId onto the
    // subscription's metadata after materialization so recurring invoices work.
    if (paymentType === 'installment') {
      sessionParams.subscription_data = {
        metadata: {
          ...(playerPaymentId ? { playerPaymentId } : {}),
          ...(pendingId       ? { pendingId       } : {}),
          coachId,
          totalMonths:    String(req._installmentTotalMonths || 0),
          remainderCents: String(req._installmentRemainderCents || 0),
        },
      };
    }

    const session = await stripe.checkout.sessions.create(sessionParams);

    console.log(`🛒  Stripe checkout created — type=${paymentType} session=${session.id}`);
    res.json({ url: session.url });

  } catch (err) {
    console.error('❌  Stripe checkout error:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── PLAYER PAYMENTS ROUTES ────────────────────────────────────

app.get('/api/coach/player-payments', requireAuth, async (req, res) => {
  try {
    const data = await PlayerPayment.find({ coach_id: req.coachId }).sort({ created_at: -1 });
    res.json({ payments: data || [] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/coach/player-payments', async (req, res) => {
  try {
    const { coachId, playerId, playerName, totalFee, depositAmount,
            paymentPlan, balance, registeredDate, paymentDeadline } = req.body;
    if (!coachId) return res.status(400).json({ message: 'coachId is required' });
    const data = await PlayerPayment.create({
      coach_id:         coachId,
      player_id:        playerId        || null,
      player_name:      playerName      || '',
      total_fee:        totalFee        || 0,
      deposit_amount:   depositAmount   || 0,
      deposit_paid:     false,
      payment_plan:     paymentPlan     || [],
      amount_paid:      0,
      balance:          balance         || totalFee || 0,
      status:           'Pending',
      registered_date:  registeredDate  || '',
      payment_deadline: paymentDeadline || '',
    });
    res.status(201).json({ message: 'Payment record created', payment: data });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/coach/player-payments/:paymentId', async (req, res) => {
  try {
    const { depositPaid, depositPaidDate, paymentPlan, amountPaid, balance, status } = req.body;
    const update = {};
    if (depositPaid !== undefined)     update.deposit_paid      = depositPaid;
    if (depositPaidDate !== undefined) update.deposit_paid_date = depositPaidDate;
    if (paymentPlan !== undefined)     update.payment_plan      = paymentPlan;
    if (amountPaid !== undefined)      update.amount_paid       = amountPaid;
    if (balance !== undefined)         update.balance           = balance;
    if (status !== undefined)          update.status            = status;
    const data = await PlayerPayment.findByIdAndUpdate(req.params.paymentId, update, { new: true });
    if (!data) return res.status(404).json({ message: 'Payment not found' });
    res.json({ message: 'Updated', payment: data });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/coach/player-payments/:paymentId', requireAuth, async (req, res) => {
  try {
    await PlayerPayment.findOneAndDelete({ _id: req.params.paymentId, coach_id: req.coachId });
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── BUDGET ROUTES ─────────────────────────────────────────────

app.get('/api/coach/budgets', requireAuth, async (req, res) => {
  try {
    const data = await Budget.find({ coach_id: req.coachId }).sort({ created_at: -1 });
    res.json({ budgets: data || [] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/coach/budgets', requireAuth, async (req, res) => {
  try {
    const existing = await Budget.findOne({ coach_id: req.coachId });
    if (existing) return res.status(409).json({ message: 'You already have a budget. Delete it first to create a new one.' });
    const {
      date, players, seasons, numEvents, eventCost, tournaments,
      headPay, asstPay, rentals, gas, hotelNights, hotelAvg, hotels,
      numUniforms, uniformCost, uniforms, equipment, insurance,
      ambassadors, others, total, perPlayer, status
    } = req.body;
    const data = await Budget.create({
      coach_id:     req.coachId,
      date,
      players:      players      || 0,
      seasons:      seasons      || 0,
      num_events:   numEvents    || 0,
      event_cost:   eventCost    || 0,
      tournaments:  tournaments  || 0,
      head_pay:     headPay      || 0,
      asst_pay:     asstPay      || 0,
      rentals:      rentals      || 0,
      gas:          gas          || 0,
      hotel_nights: hotelNights  || 0,
      hotel_avg:    hotelAvg     || 0,
      hotels:       hotels       || 0,
      num_uniforms: numUniforms  || 0,
      uniform_cost: uniformCost  || 0,
      uniforms:     uniforms     || 0,
      equipment:    equipment    || 0,
      insurance:    insurance    || 0,
      ambassadors:  ambassadors  || 0,
      others:       others       || [],
      total:        total        || 0,
      per_player:   perPlayer    || 0,
      status:       status       || 'draft',
    });
    res.status(201).json({ message: 'Budget saved', budget: data });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/coach/budgets/:budgetId', requireAuth, async (req, res) => {
  try {
    const {
      players, seasons, numEvents, eventCost, tournaments,
      headPay, asstPay, rentals, gas, hotelNights, hotelAvg, hotels,
      numUniforms, uniformCost, uniforms, equipment, insurance,
      ambassadors, others, total, perPlayer, status
    } = req.body;
    const data = await Budget.findOneAndUpdate(
      { _id: req.params.budgetId, coach_id: req.coachId },
      {
        players:      players      || 0,
        seasons:      seasons      || 0,
        num_events:   numEvents    || 0,
        event_cost:   eventCost    || 0,
        tournaments:  tournaments  || 0,
        head_pay:     headPay      || 0,
        asst_pay:     asstPay      || 0,
        rentals:      rentals      || 0,
        gas:          gas          || 0,
        hotel_nights: hotelNights  || 0,
        hotel_avg:    hotelAvg     || 0,
        hotels:       hotels       || 0,
        num_uniforms: numUniforms  || 0,
        uniform_cost: uniformCost  || 0,
        uniforms:     uniforms     || 0,
        equipment:    equipment    || 0,
        insurance:    insurance    || 0,
        ambassadors:  ambassadors  || 450,
        others:       others       || [],
        total:        total        || 0,
        per_player:   perPlayer    || 0,
        ...(status && { status }),
      },
      { new: true }
    );
    if (!data) return res.status(404).json({ message: 'Budget not found' });
    res.json({ message: 'Budget updated', budget: data });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/coach/budgets/:budgetId', requireAuth, async (req, res) => {
  try {
    await Budget.findOneAndDelete({ _id: req.params.budgetId, coach_id: req.coachId });
    res.json({ message: 'Budget deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ════════════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ════════════════════════════════════════════════════════════════

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username !== (process.env.ADMIN_USERNAME || 'admin') ||
      password !== (process.env.ADMIN_PASSWORD || 'admin123'))
    return res.status(401).json({ message: 'Invalid credentials' });
  const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '8h' });
  res.json({ token });
});

app.get('/api/admin/coaches', requireAdmin, async (req, res) => {
  try {
    const coaches = await Coach.find().select('-password').sort({ created_at: -1 });
    const regCounts = await TryoutRegistration.aggregate([
      { $group: { _id: '$coach_id', count: { $sum: 1 } } }
    ]);
    const countMap = {};
    regCounts.forEach(r => { countMap[r._id.toString()] = r.count; });
    res.json({ coaches: coaches.map(c => ({
      id:                c._id,
      firstName:         c.first_name,
      lastName:          c.last_name,
      email:             c.email,
      phone:             c.phone,
      teamName:          c.team_name,
      state:             c.state,
      location:          c.location,
      ageGroup:          c.age_group,
      image:             c.image_url || '',
      active:            c.active !== false,
      createdAt:         c.created_at,
      registrationCount: countMap[c._id.toString()] || 0,
    }))});
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/admin/coaches/:id', requireAdmin, async (req, res) => {
  try {
    const c = await Coach.findById(req.params.id).select('-password');
    if (!c) return res.status(404).json({ message: 'Coach not found' });
    const [tryouts, regs, roster, schedule] = await Promise.all([
      Tryout.find({ coach_id: c._id }),
      TryoutRegistration.find({ coach_id: c._id }).sort({ created_at: -1 }),
      Player.find({ coach_id: c._id }),
      Schedule.find({ coach_id: c._id }).sort({ date_sort: 1 }),
    ]);
    res.json({
      coach: {
        id: c._id, firstName: c.first_name, lastName: c.last_name,
        email: c.email, phone: c.phone, teamName: c.team_name,
        state: c.state, location: c.location, ageGroup: c.age_group,
        image: c.image_url || '', bio: c.bio || '',
        emailPublic: c.email_public || '', phonePublic: c.phone_public || '',
        assistant1: c.assistant1 || {}, assistant2: c.assistant2 || {},
        active: c.active !== false, createdAt: c.created_at,
      },
      tryouts, registrations: regs, roster, schedule,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/admin/coaches/:id/toggle-active', requireAdmin, async (req, res) => {
  try {
    const { active } = req.body;
    await Coach.findByIdAndUpdate(req.params.id, { active });
    res.json({ message: active ? 'Coach activated' : 'Coach deactivated', active });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/admin/coaches/:id/edit', requireAdmin, async (req, res) => {
  try {
    const { firstName, lastName, email, phone, teamName, state, location, ageGroup } = req.body;
    await Coach.findByIdAndUpdate(req.params.id, {
      first_name: firstName, last_name: lastName, email,
      phone, team_name: teamName, state, location, age_group: ageGroup,
    });
    res.json({ message: 'Coach updated' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/admin/coaches/:id/token — generate a coach JWT so admin can act as that coach
app.get('/api/admin/coaches/:id/token', requireAdmin, async (req, res) => {
  try {
    const coach = await Coach.findById(req.params.id).select('_id');
    if (!coach) return res.status(404).json({ message: 'Coach not found' });
    const token = signToken(coach._id);
    res.json({ token, coachId: coach._id });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// DELETE /api/admin/coaches/:id — delete coach account only (related data kept)
app.delete('/api/admin/coaches/:id', requireAdmin, async (req, res) => {
  try {
    const coach = await Coach.findById(req.params.id);
    if (!coach) return res.status(404).json({ message: 'Coach not found' });
    await Coach.findByIdAndDelete(req.params.id);
    res.json({ message: 'Coach deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ════════════════════════════════════════════════════════════════
//  PUBLIC ROUTES
// ════════════════════════════════════════════════════════════════

app.get('/api/teams', async (req, res) => {
  try {
    const teams = await Coach.find({ active: { $ne: false } })
      .select('first_name last_name team_name state location age_group image_url');
    res.json({ teams: teams.map(t => ({
      _id:      t._id,
      teamName: t.team_name  || '',
      state:    t.state      || '',
      location: t.location   || '',
      ageGroup: t.age_group  || '',
      imageUrl: t.image_url  || '',
    }))});
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/teams/:id', async (req, res) => {
  try {
    const team = await Coach.findById(req.params.id)
      .select('first_name last_name email_public phone_public bio image_url team_name state location age_group team_details register_enabled assistant1 assistant2');
    if (!team) return res.status(404).json({ message: 'Team not found' });
    res.json({ team: normalizeCoach(team) });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/teams/:id/tryouts', async (req, res) => {
  try {
    const tryouts = await Tryout.find({ coach_id: req.params.id }).sort({ created_at: 1 });
    res.json({ tryouts: tryouts.map(normalizeTryout) });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/teams/:id/roster', async (req, res) => {
  try {
    // ── ?paid=true — public team page: only show players with a completed checkout ──
    // Coach dashboard calls this endpoint WITHOUT ?paid=true so it always sees everyone.
    if (req.query.paid === 'true') {
      // Only filter if the team actually has a fee configured.
      // If no financials exist (no payment required) show all registered players.
      const financials = await TeamFinancials.findOne({ coach_id: req.params.id });

      if (financials && (financials.player_fee || 0) > 0) {
        // Find payment records where at least one successful payment was received
        const paidRecords = await PlayerPayment.find({
          coach_id:    req.params.id,
          amount_paid: { $gt: 0 },
        }).select('player_id');

        const paidIds = paidRecords.map(r => r.player_id).filter(Boolean);

        const players = await Player.find({
          coach_id: req.params.id,
          _id:      { $in: paidIds },
        }).sort({ created_at: 1 });

        return res.json({ players: players.map(normalizePlayer) });
      }
      // No financials / no fee set → fall through and return all players
    }

    const players = await Player.find({ coach_id: req.params.id }).sort({ created_at: 1 });
    res.json({ players: players.map(normalizePlayer) });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/teams/:id/roster', async (req, res) => {
  try {
    const {
      name, jersey, jersey2, gradYear, position, pos2, hw, city, state,
      address, zip, email, cell, dob, bats, throws, highSchool,
      motherFirst, motherLast, motherCell, motherEmail,
      fatherFirst, fatherLast, fatherCell, fatherEmail,
      teamName,
    } = req.body;
    if (!name) return res.status(400).json({ message: 'Player name is required' });
    const player = await Player.create({
      coach_id:     req.params.id,
      name,
      jersey:       jersey      || '',
      jersey_2:     jersey2     || '',
      grad_year:    gradYear    || '',
      position:     position    || '',
      pos2:         pos2        || '',
      hw:           hw          || '',
      city:         city        || '',
      state:        state       || '',
      address:      address     || '',
      zip:          zip         || '',
      email:        email       || '',
      cell:         cell        || '',
      dob:          dob         || '',
      bats:         bats        || '',
      throws:       throws      || '',
      high_school:  highSchool  || '',
      mother_first: motherFirst || '',
      mother_last:  motherLast  || '',
      mother_cell:  motherCell  || '',
      mother_email: motherEmail || '',
      father_first: fatherFirst || '',
      father_last:  fatherLast  || '',
      father_cell:  fatherCell  || '',
      father_email: fatherEmail || '',
    });
    await upsertGHLPlayer({
      name, email, cell, dob, bats, throws, hw,
      jersey, jersey2, gradYear, position, pos2,
      address, city, state, zip, highSchool,
      motherFirst, motherLast, motherCell, motherEmail,
      fatherFirst, fatherLast, fatherCell, fatherEmail,
      teamName,
    });
    res.status(201).json({ message: 'Player registered', player: normalizePlayer(player) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

app.put('/api/teams/:id/roster/:playerId', requireAuth, async (req, res) => {
  try {
    const {
      name, jersey, jersey2, gradYear, position, pos2, hw, city, state,
      address, zip, email, cell, dob, bats, throws, highSchool,
      motherFirst, motherLast, motherCell, motherEmail,
      fatherFirst, fatherLast, fatherCell, fatherEmail,
    } = req.body;
    if (!name) return res.status(400).json({ message: 'Player name is required' });
    const player = await Player.findOneAndUpdate(
      { _id: req.params.playerId, coach_id: req.params.id },
      {
        name,
        jersey:       jersey      || '',
        jersey_2:     jersey2     || '',
        grad_year:    gradYear    || '',
        position:     position    || '',
        pos2:         pos2        || '',
        hw:           hw          || '',
        city:         city        || '',
        state:        state       || '',
        address:      address     || '',
        zip:          zip         || '',
        email:        email       || '',
        cell:         cell        || '',
        dob:          dob         || '',
        bats:         bats        || '',
        throws:       throws      || '',
        high_school:  highSchool  || '',
        mother_first: motherFirst || '',
        mother_last:  motherLast  || '',
        mother_cell:  motherCell  || '',
        mother_email: motherEmail || '',
        father_first: fatherFirst || '',
        father_last:  fatherLast  || '',
        father_cell:  fatherCell  || '',
        father_email: fatherEmail || '',
      },
      { new: true }
    );
    if (!player) return res.status(404).json({ message: 'Player not found' });
    res.json({ message: 'Player updated', player: normalizePlayer(player) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

app.delete('/api/teams/:id/roster/:playerId', requireAuth, async (req, res) => {
  try {
    await Player.findOneAndDelete({ _id: req.params.playerId, coach_id: req.params.id });
    res.json({ message: 'Player deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

app.get('/api/teams/:id/schedule', async (req, res) => {
  try {
    const data = await Schedule.find({ coach_id: req.params.id }).sort({ date_sort: 1 });
    res.json({ schedule: data.map(normalizeGame) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/teams/:id/financials', async (req, res) => {
  try {
    const data = await TeamFinancials.findOne({ coach_id: req.params.id });
    res.json({ financials: data || null });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/teams/:id/tryout-registrations', async (req, res) => {
  try {
    const { completedBy, name, address, city, state, zip, cell, email,
            playerName, age, dob, hw, pos1, pos2, tryoutDate, successUrl, cancelUrl } = req.body;
    if (!name || !playerName) return res.status(400).json({ message: 'Name and player name are required' });

    // ── Look up the tryout to check if it has a fee ───────────
    const tryout = await Tryout.findOne({ coach_id: req.params.id, date: tryoutDate });
    const tryoutFeeAmount = tryout ? parseFloat((tryout.fee || '').replace('$', '')) : NaN;
    const isPaid = tryout && tryout.stripe_price_id && !isNaN(tryoutFeeAmount) && tryoutFeeAmount > 0;

    // ── Save registration — pending_payment if paid, confirmed if free ──
    const reg = await TryoutRegistration.create({
      coach_id:     req.params.id,
      completed_by: completedBy || '',
      name,
      address:      address     || '',
      city:         city        || '',
      state:        state       || '',
      zip:          zip         || '',
      cell:         cell        || '',
      email:        email       || '',
      player_name:  playerName,
      age:          age         || '',
      dob:          dob         || '',
      hw:           hw          || '',
      pos1:         pos1        || '',
      pos2:         pos2        || '',
      tryout_date:  tryoutDate  || '',
      status:       isPaid ? 'pending_payment' : 'confirmed',
      // Only paid tryouts get a 72h expiry — abandoned checkouts will be
      // auto-deleted by the partial TTL index. Confirmed tryouts (free, or
      // paid + completed) are immune from TTL deletion.
      expires_at:   isPaid ? new Date(Date.now() + 72 * 60 * 60 * 1000) : undefined,
    });

    // ── If paid, create Stripe checkout and return URL ────────
    if (isPaid && stripe) {
      try {
        const session = await stripe.checkout.sessions.create({
          mode:        'payment',
          line_items:  [{ price: tryout.stripe_price_id, quantity: 1 }],
          success_url: successUrl || `${req.headers.origin || ''}?tryout_payment=success`,
          cancel_url:  cancelUrl  || `${req.headers.origin || ''}?tryout_payment=cancelled`,
          // Shows Stripe's built-in "Add promotion code" field on checkout.
          allow_promotion_codes: true,
          metadata: {
            paymentType:    'tryout',
            registrationId: String(reg._id),
            coachId:        String(req.params.id),
          },
        });
        console.log(`🛒  Tryout checkout created — registrationId=${reg._id} session=${session.id}`);
        return res.status(201).json({ message: 'Proceed to payment', checkoutUrl: session.url, registration: reg });
      } catch (stripeErr) {
        console.error('❌  Tryout checkout creation failed:', stripeErr.message);
        // Stripe failed — delete the pending record so the player can retry cleanly
        await TryoutRegistration.findByIdAndDelete(reg._id);
        return res.status(500).json({ message: 'Payment setup failed. Please try again.' });
      }
    }

    // ── Free tryout — GHL upsert and return success ───────────
    const ghlResult = await upsertGHLContact({
      completedBy, name, address, city, state, zip, cell, email,
      playerName, age, dob, hw, pos1, pos2, tryoutDate,
    });

    // ── Notify coach + Mark (free tryout) ─────────────────────────
    // Two sends, same body, different subjects:
    //   1) Coach: short congrats subject (only if they have an email)
    //   2) Mark:  detailed subject with player + coach + team
    const coachRec = await Coach.findById(req.params.id).select('first_name last_name team_name email').catch(() => null);
    const coachFullName = coachRec ? `${coachRec.first_name || ''} ${coachRec.last_name || ''}`.trim() : '';
    const teamName = coachRec?.team_name || '';

    const tryoutPayload = {
      coachName:       coachFullName,
      teamName,
      registrantName:  name,
      registrantCell:  cell,
      registrantEmail: email,
      playerName,
      age, dob, pos1, pos2, hw,
      address, city, state, zip,
      tryoutDate,
      isPaid: false,
    };

    // (1) Coach — short congrats subject
    if (coachRec?.email) {
      try {
        await sendCoachTryoutNotificationEmail({
          ...tryoutPayload,
          subject:    'Congratulations! A new player has registered for your tryout.',
          recipients: coachRec.email,
        });
      } catch (e) { console.error('⚠️  Coach tryout email error (free, coach):', e.message); }
    }

    // (2) Mark — detailed subject
    try {
      const markSubject = `New Tryout Registration — ${playerName || 'Player'} with Coach ${coachFullName || 'Unknown'} (${teamName || 'Unknown Team'})`;
      await sendCoachTryoutNotificationEmail({
        ...tryoutPayload,
        subject:    markSubject,
        recipients: 'mark@markhelsel.com',
      });
    } catch (e) { console.error('⚠️  Coach tryout email error (free, mark):', e.message); }

    res.status(201).json({ message: 'Registration submitted', registration: reg, ghl: ghlResult });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── PENDING REGISTRATION (used by public registration forms) ─────
// Replaces the old "create Player + create PlayerPayment up front" pattern.
// The form payload is stashed here, the _id is handed to Stripe checkout in
// session metadata, and the webhook materializes Player + PlayerPayment + GHL
// only after payment succeeds. Abandoned pendings auto-expire via TTL (48h).
app.post('/api/registrations/pending', async (req, res) => {
  try {
    const {
      coachId,
      // Player payload — accepts every field both registration forms send.
      name, jersey, jersey2, gradYear, position, pos2, hw, city, state,
      address, zip, email, cell, dob, bats, throws, highSchool,
      motherFirst, motherLast, motherCell, motherEmail,
      fatherFirst, fatherLast, fatherCell, fatherEmail,
      teamName,
      // Payment-snapshot fields — captured at submit time so we know what
      // the parent saw and agreed to.
      totalFee, depositAmount, paymentPlan, paymentDeadline, registeredDate,
    } = req.body;

    if (!coachId) return res.status(400).json({ message: 'coachId is required' });
    if (!name)    return res.status(400).json({ message: 'Player name is required' });

    const pending = await PendingRegistration.create({
      coach_id:        coachId,
      player_payload:  {
        name, jersey, jersey2, gradYear, position, pos2, hw, city, state,
        address, zip, email, cell, dob, bats, throws, highSchool,
        motherFirst, motherLast, motherCell, motherEmail,
        fatherFirst, fatherLast, fatherCell, fatherEmail,
      },
      total_fee:       Number(totalFee)      || 0,
      deposit_amount:  Number(depositAmount) || 0,
      payment_plan:    Array.isArray(paymentPlan) ? paymentPlan : [],
      payment_deadline:paymentDeadline || '',
      registered_date: registeredDate  || new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }),
      team_name:       teamName        || '',
    });

    console.log(`📥  PendingRegistration created — pendingId=${pending._id} player="${name}" coachId=${coachId}`);
    res.status(201).json({ message: 'Pending registration created', pendingId: pending._id });
  } catch (err) {
    console.error('❌  PendingRegistration create error:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════
//  FINANCIAL MANAGEMENT — ADMIN ROUTES
//  Read-only aggregates + coach payout recording.
//  All routes protected by requireAdmin.
// ══════════════════════════════════════════════════════════════════

const FIN_ORG_FEE_PER_PLAYER = 450; // org's fixed cut per registered player
const finRound2 = n => Math.round((Number(n) || 0) * 100) / 100;
function finTeamName(c) {
  return c.team_name || `${c.first_name || ''} ${c.last_name || ''}`.trim() || 'Unnamed Team';
}
function finCoachName(c) {
  return `${c.first_name || ''} ${c.last_name || ''}`.trim() || '—';
}
function finDerivedStatus(p) {
  const paid = Number(p.amount_paid) || 0;
  const bal  = Number(p.balance) || 0;
  if (paid === 0) return 'unpaid';
  if (bal  === 0) return 'paid';
  return 'partial';
}
function finEscapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// GET /api/admin/fin/organization-overview
app.get('/api/admin/fin/organization-overview', requireAdmin, async (req, res) => {
  try {
    const activeCoaches = await Coach.find({ active: { $ne: false } }).select('_id').lean();
    const activeCoachIds = activeCoaches.map(c => c._id);
    const activeTeams    = activeCoachIds.length;
    if (activeTeams === 0) {
      return res.json({ activeTeams: 0, averagePlayerFee: 0, totalCollected: 0, outstanding: 0, payingPlayers: 0, totalPlayers: 0, organizationProfit: 0, totalBudget: 0, budgetedOrganizationProfit: 0, budgetBalanceRemaining: 0 });
    }
    const [budgets, paymentAgg, playerStats] = await Promise.all([
      Budget.aggregate([
        { $match: { coach_id: { $in: activeCoachIds } } },
        { $sort: { created_at: -1 } },
        { $group: { _id: '$coach_id', total: { $first: '$total' }, players: { $first: '$players' } } },
      ]),
      PlayerPayment.aggregate([
        { $match: { coach_id: { $in: activeCoachIds }, status: { $in: ['Partial', 'Paid'] } } },
        { $group: { _id: null, collected: { $sum: '$amount_paid' }, outstanding: { $sum: '$balance' } } },
      ]),
      // totalRegistered: all PlayerPayment docs
      // fullyPaid: balance = 0 AND amount_paid > 0
      // notFullyPaid = totalRegistered - fullyPaid
      // organizationProfit = totalRegistered * 450
      PlayerPayment.aggregate([
        { $match: { coach_id: { $in: activeCoachIds }, status: { $in: ['Partial', 'Paid'] } } },
        { $group: {
            _id:         null,
            total:       { $sum: 1 },
            fullyPaid:   { $sum: { $cond: [{ $and: [{ $eq: ['$balance', 0] }, { $gt: ['$amount_paid', 0] }] }, 1, 0] } },
        }},
      ]),
    ]);
    
    // Calculate average player fee: for each team (Budget ÷ Paying Players from budget submission), then average across teams
    let totalPlayerFees = 0;
    let teamsWithValidFee = 0;
    // totalBudget: sum of every active team's budget total.
    // budgetedPlayers: sum of the "paying players" each coach entered in their
    // budget calculator — used for the budget-based organization profit card.
    let totalBudget = 0;
    let budgetedPlayers = 0;
    
    budgets.forEach(budget => {
      const budgetTotal = budget.total ?? 0;
      const payingPlayers = budget.players ?? 0;
      
      totalBudget += budgetTotal;
      budgetedPlayers += payingPlayers;
      
      if (budgetTotal > 0 && payingPlayers > 0) {
        totalPlayerFees += budgetTotal / payingPlayers;
        teamsWithValidFee++;
      }
    });
    
    const averagePlayerFee = teamsWithValidFee > 0 ? finRound2(totalPlayerFees / teamsWithValidFee) : 0;
    // Budget-based organization profit: sum of budgeted paying players × $450.
    // Distinct from organizationProfit, which uses actual registered players.
    const budgetedOrganizationProfit = finRound2(budgetedPlayers * 450);
    
    const totalRegistered  = playerStats[0]?.total     ?? 0;
    const fullyPaid        = playerStats[0]?.fullyPaid ?? 0;
    const notFullyPaid     = totalRegistered - fullyPaid;
    const organizationProfit = finRound2(totalRegistered * 450);
    const orgTotalCollected = finRound2(paymentAgg[0]?.collected ?? 0);
    // Balance left to meet the combined budget of all active teams.
    // Clamped at 0 so it never goes negative once collections exceed budget.
    const budgetBalanceRemaining = finRound2(Math.max(totalBudget - orgTotalCollected, 0));
    res.json({
      activeTeams,
      averagePlayerFee,
      totalCollected:     orgTotalCollected,
      outstanding:        finRound2(paymentAgg[0]?.outstanding ?? 0),
      notFullyPaid,
      totalRegistered,
      organizationProfit,
      totalBudget:                 finRound2(totalBudget),
      budgetedOrganizationProfit,
      budgetBalanceRemaining,
    });
  } catch (err) {
    console.error('fin org overview error:', err);
    res.status(500).json({ message: 'Failed to load organization overview' });
  }
});

// GET /api/admin/fin/teams  — lightweight list for dropdown
app.get('/api/admin/fin/teams', requireAdmin, async (req, res) => {
  try {
    const coaches = await Coach.find({ active: { $ne: false } }).select('_id first_name last_name team_name').lean();
    const teams = coaches
      .map(c => ({ id: c._id, name: finTeamName(c), coach: finCoachName(c) }))
      .sort((a, b) => a.name.localeCompare(b.name));
    res.json({ teams });
  } catch (err) {
    res.status(500).json({ message: 'Failed to load teams' });
  }
});

// GET /api/admin/fin/team-rankings?sortBy=budget|balance|completed
app.get('/api/admin/fin/team-rankings', requireAdmin, async (req, res) => {
  try {
    const sortBy = String(req.query.sortBy || 'budget');
    // Core sort keys + budget-calculator line-item keys.
    // The budget keys map to fields on the Budget document and let admins
    // rank teams by any single cost category (e.g. highest head coach pay).
    const BUDGET_SORT_FIELDS = {
      tournaments:  'tournaments',
      headPay:      'head_pay',
      asstPay:      'asst_pay',
      rentals:      'rentals',
      gas:          'gas',
      hotels:       'hotels',
      uniforms:     'uniforms',
      equipment:    'equipment',
      insurance:    'insurance',
      ambassadors:  'ambassadors',
      players:      'players',
      seasons:      'seasons',
      perPlayer:    'per_player',
      others:       'others',
    };
    if (!['budget', 'balance', 'completed'].includes(sortBy) && !BUDGET_SORT_FIELDS[sortBy]) {
      return res.status(400).json({ message: 'Invalid sortBy' });
    }
    const activeCoaches  = await Coach.find({ active: { $ne: false } }).select('_id first_name last_name team_name').lean();
    const activeCoachIds = activeCoaches.map(c => c._id);
    if (activeCoachIds.length === 0) return res.json({ rankings: [] });
    const [budgets, payments] = await Promise.all([
      Budget.aggregate([
        { $match: { coach_id: { $in: activeCoachIds } } },
        { $sort: { created_at: -1 } },
        { $group: {
            _id:         '$coach_id',
            total:       { $first: '$total' },
            tournaments: { $first: '$tournaments' },
            head_pay:    { $first: '$head_pay' },
            asst_pay:    { $first: '$asst_pay' },
            rentals:     { $first: '$rentals' },
            gas:         { $first: '$gas' },
            hotels:      { $first: '$hotels' },
            uniforms:    { $first: '$uniforms' },
            equipment:   { $first: '$equipment' },
            insurance:   { $first: '$insurance' },
            ambassadors: { $first: '$ambassadors' },
            players:     { $first: '$players' },
            seasons:     { $first: '$seasons' },
            per_player:  { $first: '$per_player' },
            others:      { $first: '$others' },
        } },
      ]),
      PlayerPayment.aggregate([
        { $match: { coach_id: { $in: activeCoachIds }, status: { $in: ['Partial', 'Paid'] } } },
        { $group: { _id: '$coach_id', collected: { $sum: '$amount_paid' }, balance: { $sum: '$balance' } } },
      ]),
    ]);
    const budgetByCoach  = Object.fromEntries(budgets .map(b => [String(b._id), b]));
    const paymentByCoach = Object.fromEntries(payments.map(p => [String(p._id), p]));
    let rows = activeCoaches.map(c => {
      const bdg          = budgetByCoach[String(c._id)] || {};
      const budgetRaw    = bdg.total ?? 0;
      const p            = paymentByCoach[String(c._id)] || { collected: 0, balance: 0 };
      const collectedRaw = p.collected;
      const balanceRaw   = p.balance;
      const percentCollected = budgetRaw > 0 ? finRound2(Math.min(100, (collectedRaw / budgetRaw) * 100)) : 0;
      const completed = budgetRaw > 0 && collectedRaw >= budgetRaw;
      return { 
        id: c._id, 
        name: finTeamName(c), 
        coach: finCoachName(c), 
        budget: finRound2(budgetRaw), 
        collected: finRound2(collectedRaw), 
        balance: finRound2(balanceRaw), 
        percentCollected, 
        completed,
        // Budget calculator line items — included so the UI can display the
        // active sort metric alongside the existing stats.
        tournaments: finRound2(bdg.tournaments ?? 0),
        headPay:     finRound2(bdg.head_pay    ?? 0),
        asstPay:     finRound2(bdg.asst_pay    ?? 0),
        rentals:     finRound2(bdg.rentals     ?? 0),
        gas:         finRound2(bdg.gas         ?? 0),
        hotels:      finRound2(bdg.hotels      ?? 0),
        uniforms:    finRound2(bdg.uniforms    ?? 0),
        equipment:   finRound2(bdg.equipment   ?? 0),
        insurance:   finRound2(bdg.insurance   ?? 0),
        ambassadors: finRound2(bdg.ambassadors ?? 0),
        players:     finRound2(bdg.players    ?? 0),
        seasons:     finRound2(bdg.seasons    ?? 0),
        perPlayer:   finRound2(bdg.per_player ?? 0),
        others:      finRound2(Array.isArray(bdg.others) ? bdg.others.reduce((s, o) => s + (Number(o?.amt) || 0), 0) : 0),
      };
    });
    // Filter and sort based on sortBy parameter
    if (sortBy === 'budget') {
      rows.sort((a, b) => b.budget - a.budget || a.name.localeCompare(b.name));
    } else if (sortBy === 'balance') {
      rows.sort((a, b) => b.balance - a.balance || a.name.localeCompare(b.name));
    } else if (BUDGET_SORT_FIELDS[sortBy]) {
      // Budget line-item sort — highest value first, tie-break by name.
      rows.sort((a, b) => b[sortBy] - a[sortBy] || a.name.localeCompare(b.name));
    } else {
      // For 'completed': sort all teams by % collected descending (highest % = top rank)
      rows.sort((a, b) => b.percentCollected - a.percentCollected || a.name.localeCompare(b.name));
    }
    res.json({ rankings: rows });
  } catch (err) {
    res.status(500).json({ message: 'Failed to load team rankings' });
  }
});

// GET /api/admin/fin/teams/:coachId  — team financial metrics
app.get('/api/admin/fin/teams/:coachId', requireAdmin, async (req, res) => {
  try {
    const { coachId } = req.params;
    if (!mongoose.isValidObjectId(coachId)) return res.status(400).json({ message: 'Invalid team id' });
    const coach = await Coach.findOne({ _id: coachId, active: { $ne: false } }).select('_id first_name last_name team_name').lean();
    if (!coach) return res.status(404).json({ message: 'Team not found' });
    const coachObjId = new mongoose.Types.ObjectId(coachId);
    const [financials, latestBudget, paymentAgg, playerStats] = await Promise.all([
      TeamFinancials.findOne({ coach_id: coachId }).select('payment_deadline').lean(),
      Budget.findOne({ coach_id: coachId }).sort({ created_at: -1 }).select('total players').lean(),
      PlayerPayment.aggregate([
        { $match: { coach_id: coachObjId, status: { $in: ['Partial', 'Paid'] } } },
        { $group: { _id: null, collected: { $sum: '$amount_paid' }, balance: { $sum: '$balance' } } },
      ]),
      PlayerPayment.aggregate([
        { $match: { coach_id: coachObjId, status: { $in: ['Partial', 'Paid'] } } },
        { $group: { _id: null,
            total:      { $sum: 1 },
            fullyPaid:  { $sum: { $cond: [{ $and: [{ $eq: ['$balance', 0] }, { $gt: ['$amount_paid', 0] }] }, 1, 0] } },
            hasBalance: { $sum: { $cond: [{ $gt: ['$balance', 0] }, 1, 0] } },
        }},
      ]),
    ]);
    const dl = financials?.payment_deadline ? new Date(financials.payment_deadline) : null;
    const deadlinePassed = !!(dl && dl < new Date());
    const accountsInRed  = deadlinePassed ? (playerStats[0]?.hasBalance ?? 0) : 0;
    res.json({
      id: coach._id, name: finTeamName(coach), coach: finCoachName(coach),
      budget:           finRound2(latestBudget?.total    ?? 0),
      budgetedPlayers:  latestBudget?.players             ?? 0,
      totalCollected:   finRound2(paymentAgg[0]?.collected ?? 0),
      balanceRemaining: finRound2(paymentAgg[0]?.balance   ?? 0),
      paymentDeadline:  financials?.payment_deadline       || null,
      deadlinePassed,
      totalRegistered:  playerStats[0]?.total             ?? 0,
      goodStanding:     playerStats[0]?.fullyPaid         ?? 0,
      accountsInRed,
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to load team' });
  }
});

// GET /api/admin/fin/teams/:coachId/players?page&perPage&search&status
app.get('/api/admin/fin/teams/:coachId/players', requireAdmin, async (req, res) => {
  try {
    const { coachId } = req.params;
    if (!mongoose.isValidObjectId(coachId)) return res.status(400).json({ message: 'Invalid team id' });
    const coachExists = await Coach.exists({ _id: coachId, active: { $ne: false } });
    if (!coachExists) return res.status(404).json({ message: 'Team not found' });
    const page    = Math.max(1, parseInt(req.query.page,    10) || 1);
    const perPage = Math.min(100, Math.max(1, parseInt(req.query.perPage, 10) || 20));
    const search  = (req.query.search || '').trim();
    const status  = req.query.status;
    const filter  = { coach_id: coachId, status: { $in: ['Partial', 'Paid'] } };
    if (search) filter.player_name = { $regex: finEscapeRegex(search), $options: 'i' };
    if      (status === 'paid')    { filter.amount_paid = { $gt: 0 }; filter.balance = 0; }
    else if (status === 'partial') { filter.amount_paid = { $gt: 0 }; filter.balance = { $gt: 0 }; }
    else if (status === 'unpaid')  { filter.amount_paid = 0; }
    else if (status === 'overdue') { filter.balance = { $gt: 0 }; }
    const [total, players] = await Promise.all([
      PlayerPayment.countDocuments(filter),
      PlayerPayment.find(filter).sort({ player_name: 1 }).skip((page - 1) * perPage).limit(perPage).lean(),
    ]);
    res.json({
      players: players.map(p => ({
        id: p._id, name: p.player_name || '—',
        totalFee:    finRound2(p.total_fee),
        paidAmount:  finRound2(p.amount_paid),
        balance:     finRound2(p.balance),
        status:      finDerivedStatus(p),
        lastPayment: p.updated_at || null,
      })),
      total, page, perPage,
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to load players' });
  }
});

// GET /api/admin/fin/outstanding-balances?page&perPage
app.get('/api/admin/fin/outstanding-balances', requireAdmin, async (req, res) => {
  try {
    const page    = Math.max(1, parseInt(req.query.page,    10) || 1);
    const perPage = Math.min(100, Math.max(1, parseInt(req.query.perPage, 10) || 20));
    const activeCoaches = await Coach.find({ active: { $ne: false } }).select('_id team_name first_name last_name').lean();
    const activeCoachIds = activeCoaches.map(c => c._id);
    if (activeCoachIds.length === 0) return res.json({ players: [], total: 0, page, perPage });
    const teamNameMap = Object.fromEntries(activeCoaches.map(c => [String(c._id), finTeamName(c)]));
    const filter = { coach_id: { $in: activeCoachIds }, status: { $in: ['Partial', 'Paid'] }, balance: { $gt: 0 } };
    const [total, players] = await Promise.all([
      PlayerPayment.countDocuments(filter),
      PlayerPayment.find(filter).sort({ balance: -1, player_name: 1 }).skip((page - 1) * perPage).limit(perPage).lean(),
    ]);
    res.json({
      players: players.map(p => ({
        id: p._id, name: p.player_name || '—',
        team:       teamNameMap[String(p.coach_id)] || '—',
        totalFee:   finRound2(p.total_fee),
        paidAmount: finRound2(p.amount_paid),
        balance:    finRound2(p.balance),
        status:     finDerivedStatus(p),
      })),
      total, page, perPage,
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to load outstanding balances' });
  }
});

// GET /api/admin/fin/teams/:coachId/payouts
app.get('/api/admin/fin/teams/:coachId/payouts', requireAdmin, async (req, res) => {
  try {
    const { coachId } = req.params;
    if (!mongoose.isValidObjectId(coachId)) return res.status(400).json({ message: 'Invalid team id' });
    const coachExists = await Coach.exists({ _id: coachId, active: { $ne: false } });
    if (!coachExists) return res.status(404).json({ message: 'Team not found' });
    res.json(await finGetPayoutSummary(coachId));
  } catch (err) {
    res.status(500).json({ message: 'Failed to load payouts' });
  }
});

// POST /api/admin/fin/teams/:coachId/payouts
app.post('/api/admin/fin/teams/:coachId/payouts', requireAdmin, async (req, res) => {
  try {
    const { coachId } = req.params;
    if (!mongoose.isValidObjectId(coachId)) return res.status(400).json({ message: 'Invalid team id' });
    const coachExists = await Coach.exists({ _id: coachId, active: { $ne: false } });
    if (!coachExists) return res.status(404).json({ message: 'Team not found' });
    const { date, amount, notes } = req.body;
    const parsedAmount = parseFloat(amount);
    if (!date || isNaN(new Date(date).getTime())) return res.status(400).json({ message: 'A valid date is required' });
    if (!parsedAmount || parsedAmount <= 0) return res.status(400).json({ message: 'Amount must be a positive number' });
    await CoachPayout.create({ coach_id: coachId, date: new Date(date), amount: finRound2(parsedAmount), notes: (notes || '').trim().slice(0, 500) });
    res.status(201).json(await finGetPayoutSummary(coachId));
  } catch (err) {
    res.status(500).json({ message: 'Failed to save payout' });
  }
});

// PUT /api/admin/fin/teams/:coachId/payouts/:payoutId
app.put('/api/admin/fin/teams/:coachId/payouts/:payoutId', requireAdmin, async (req, res) => {
  try {
    const { coachId, payoutId } = req.params;
    if (!mongoose.isValidObjectId(coachId))  return res.status(400).json({ message: 'Invalid team id' });
    if (!mongoose.isValidObjectId(payoutId)) return res.status(400).json({ message: 'Invalid payout id' });
    const coachExists = await Coach.exists({ _id: coachId, active: { $ne: false } });
    if (!coachExists) return res.status(404).json({ message: 'Team not found' });
    const { date, amount, notes } = req.body;
    const parsedAmount = parseFloat(amount);
    if (!date || isNaN(new Date(date).getTime())) return res.status(400).json({ message: 'A valid date is required' });
    if (!parsedAmount || parsedAmount <= 0) return res.status(400).json({ message: 'Amount must be a positive number' });
    const updated = await CoachPayout.findOneAndUpdate(
      { _id: payoutId, coach_id: coachId },
      { date: new Date(date), amount: finRound2(parsedAmount), notes: (notes || '').trim().slice(0, 500) },
      { new: true }
    );
    if (!updated) return res.status(404).json({ message: 'Payment not found' });
    res.json(await finGetPayoutSummary(coachId));
  } catch (err) {
    res.status(500).json({ message: 'Failed to update payout' });
  }
});

// DELETE /api/admin/fin/teams/:coachId/payouts/:payoutId
app.delete('/api/admin/fin/teams/:coachId/payouts/:payoutId', requireAdmin, async (req, res) => {
  try {
    const { coachId, payoutId } = req.params;
    if (!mongoose.isValidObjectId(coachId))  return res.status(400).json({ message: 'Invalid team id' });
    if (!mongoose.isValidObjectId(payoutId)) return res.status(400).json({ message: 'Invalid payout id' });
    const coachExists = await Coach.exists({ _id: coachId, active: { $ne: false } });
    if (!coachExists) return res.status(404).json({ message: 'Team not found' });
    const deleted = await CoachPayout.findOneAndDelete({ _id: payoutId, coach_id: coachId });
    if (!deleted) return res.status(404).json({ message: 'Payment not found' });
    res.json(await finGetPayoutSummary(coachId));
  } catch (err) {
    res.status(500).json({ message: 'Failed to delete payout' });
  }
});

async function finGetPayoutSummary(coachId) {
  const coachObjId = new mongoose.Types.ObjectId(coachId);
  const [owedAgg, payouts] = await Promise.all([
    PlayerPayment.aggregate([
      { $match: { coach_id: coachObjId, status: { $in: ['Partial', 'Paid'] }, amount_paid: { $gt: 0 } } },
      { $group: { _id: null, totalOwed: { $sum: { $max: [{ $subtract: ['$total_fee', FIN_ORG_FEE_PER_PLAYER] }, 0] } } } },
    ]),
    CoachPayout.find({ coach_id: coachId }).sort({ date: -1 }).lean(),
  ]);
  const totalOwedToCoach = finRound2(owedAgg[0]?.totalOwed ?? 0);
  const totalPaidToCoach = finRound2(payouts.reduce((s, p) => s + p.amount, 0));
  return {
    totalOwedToCoach,
    totalPaidToCoach,
    balanceToBePaid:  finRound2(totalOwedToCoach - totalPaidToCoach),
    orgFeePerPlayer:  FIN_ORG_FEE_PER_PLAYER,
    payouts: payouts.map(p => ({ id: p._id, date: p.date, amount: p.amount, notes: p.notes || '' })),
  };
}


// ── COACH FINANCIAL DASHBOARD ROUTES ─────────────────────────────
// Protected by requireAuth (coach JWT). Coach sees only their own team.
// No payout data exposed — that is admin-only.

// GET /api/coach/fin/overview
app.get('/api/coach/fin/overview', requireAuth, async (req, res) => {
  try {
    const coachId    = req.coachId;
    const coachObjId = new mongoose.Types.ObjectId(coachId);
    const [coach, financials, latestBudget, paymentAgg, playerStats] = await Promise.all([
      Coach.findById(coachId).select('first_name last_name team_name').lean(),
      TeamFinancials.findOne({ coach_id: coachId }).select('payment_deadline').lean(),
      Budget.findOne({ coach_id: coachId }).sort({ created_at: -1 }).select('total players').lean(),
      PlayerPayment.aggregate([
        { $match: { coach_id: coachObjId, status: { $in: ['Partial', 'Paid'] } } },
        { $group: { _id: null, collected: { $sum: '$amount_paid' }, balance: { $sum: '$balance' } } },
      ]),
      PlayerPayment.aggregate([
        { $match: { coach_id: coachObjId, status: { $in: ['Partial', 'Paid'] } } },
        { $group: { _id: null,
            total:      { $sum: 1 },
            fullyPaid:  { $sum: { $cond: [{ $and: [{ $eq: ['$balance', 0] }, { $gt: ['$amount_paid', 0] }] }, 1, 0] } },
            hasBalance: { $sum: { $cond: [{ $gt: ['$balance', 0] }, 1, 0] } },
        }},
      ]),
    ]);
    if (!coach) return res.status(404).json({ message: 'Coach not found' });
    const teamName   = coach.team_name || `${coach.first_name || ''} ${coach.last_name || ''}`.trim() || 'My Team';
    const coachName  = `${coach.first_name || ''} ${coach.last_name || ''}`.trim() || '—';
    const dl         = financials?.payment_deadline ? new Date(financials.payment_deadline) : null;
    const deadlinePassed = !!(dl && dl < new Date());
    const accountsInRed  = deadlinePassed ? (playerStats[0]?.hasBalance ?? 0) : 0;
    res.json({
      id:               coachId,
      name:             teamName,
      coach:            coachName,
      budget:           finRound2(latestBudget?.total    ?? 0),
      budgetedPlayers:  latestBudget?.players             ?? 0,
      totalCollected:   finRound2(paymentAgg[0]?.collected ?? 0),
      balanceRemaining: finRound2(paymentAgg[0]?.balance   ?? 0),
      paymentDeadline:  financials?.payment_deadline       || null,
      deadlinePassed,
      totalRegistered:  playerStats[0]?.total             ?? 0,
      goodStanding:     playerStats[0]?.fullyPaid         ?? 0,
      accountsInRed,
    });
  } catch (err) {
    console.error('coach fin overview error:', err);
    res.status(500).json({ message: 'Failed to load financial overview' });
  }
});

// GET /api/coach/fin/players?page&perPage&search&status
app.get('/api/coach/fin/players', requireAuth, async (req, res) => {
  try {
    const coachId = req.coachId;
    const page    = Math.max(1, parseInt(req.query.page,    10) || 1);
    const perPage = Math.min(100, Math.max(1, parseInt(req.query.perPage, 10) || 20));
    const search  = (req.query.search || '').trim();
    const status  = req.query.status;
    const filter  = { coach_id: coachId, status: { $in: ['Partial', 'Paid'] } };
    if (search) filter.player_name = { $regex: finEscapeRegex(search), $options: 'i' };
    if      (status === 'paid')    { filter.amount_paid = { $gt: 0 }; filter.balance = 0; }
    else if (status === 'partial') { filter.amount_paid = { $gt: 0 }; filter.balance = { $gt: 0 }; }
    else if (status === 'unpaid')  { filter.amount_paid = 0; }
    else if (status === 'overdue') { filter.balance = { $gt: 0 }; }
    const [total, players] = await Promise.all([
      PlayerPayment.countDocuments(filter),
      PlayerPayment.find(filter).sort({ player_name: 1 }).skip((page - 1) * perPage).limit(perPage).lean(),
    ]);
    res.json({
      players: players.map(p => ({
        id:          p._id,
        name:        p.player_name || '—',
        totalFee:    finRound2(p.total_fee),
        paidAmount:  finRound2(p.amount_paid),
        balance:     finRound2(p.balance),
        status:      finDerivedStatus(p),
        lastPayment: p.updated_at || null,
      })),
      total, page, perPage,
    });
  } catch (err) {
    console.error('coach fin players error:', err);
    res.status(500).json({ message: 'Failed to load players' });
  }
});

// GET /api/coach/fin/payouts  — read-only; coach sees only their own payouts
app.get('/api/coach/fin/payouts', requireAuth, async (req, res) => {
  try {
    res.json(await finGetPayoutSummary(req.coachId));
  } catch (err) {
    console.error('coach fin payouts error:', err);
    res.status(500).json({ message: 'Failed to load payouts' });
  }
});

// ── VERCEL SERVERLESS EXPORT ────────────────────────────────────────────────
// ── START SERVER ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`🚀  Server running on port ${PORT}`);
});
