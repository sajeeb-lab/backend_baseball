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
async function sendPaymentNotificationEmail({ playerName, paymentType, amountPaid, totalFee, balance, status, playerEmail, playerCell, coachName, teamName, coachEmail }) {
  const notifyEmail = 'sajeeb.codes@gmail.com';
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.warn('⚠️  EMAIL_USER / EMAIL_PASS not set — skipping payment notification email');
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
        <tr style="background:#f4f6f9"><td style="padding:9px 12px;color:#5a6a7a">Coach</td><td style="padding:9px 12px;color:#0a1628">${coachName || '—'}</td></tr>
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
    const recipients = [notifyEmail, coachEmail].filter(Boolean).join(', ');
    await createTransporter().sendMail({
      from: `"Ambassadors Baseball" <${process.env.EMAIL_USER}>`,
      to: recipients,
      subject: `Payment Received — ${playerName || 'Player'} (${typeLabel})`,
      html,
    });
    console.log(`📧  Payment notification email sent to ${recipients}`);
  } catch (err) {
    console.error('⚠️  Failed to send payment notification email:', err.message);
  }
}

// ── ENV VALIDATION ────────────────────────────────────────────────
const REQUIRED_ENV = ['MONGODB_URI', 'JWT_SECRET'];
// GHL_API_KEY / GHL_LOCATION_ID are optional — used only for contact upserts
// STRIPE_SECRET_KEY is optional — needed for checkout but not fatal at startup
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length) {
  console.error('❌  Missing required environment variables:', missingEnv.join(', '));
  process.exit(1);
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
    const { playerPaymentId, paymentType, coachId } = session.metadata || {};
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
            update.amount_paid = existing.total_fee;
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

          // ── Send payment notification email ───────────────────
          try {
            const updatedPmt = await PlayerPayment.findById(playerPaymentId);
            const playerRec  = updatedPmt?.player_id ? await Player.findById(updatedPmt.player_id).select('email cell') : null;
            const coachRec   = updatedPmt?.coach_id  ? await Coach.findById(updatedPmt.coach_id).select('first_name last_name team_name email') : null;
            await sendPaymentNotificationEmail({
              playerName:  updatedPmt?.player_name || '',
              paymentType,
              amountPaid:  updatedPmt?.amount_paid ?? 0,
              totalFee:    updatedPmt?.total_fee   ?? 0,
              balance:     updatedPmt?.balance     ?? 0,
              status:      updatedPmt?.status      || '',
              playerEmail: playerRec?.email        || '',
              playerCell:  playerRec?.cell         || '',
              coachName:   coachRec ? `${coachRec.first_name} ${coachRec.last_name}` : '',
              teamName:    coachRec?.team_name     || '',
              coachEmail:  coachRec?.email         || '',
            });
          } catch (emailErr) {
            console.error('⚠️  Payment notification email error (checkout):', emailErr.message);
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
        try {
          await TryoutRegistration.findByIdAndUpdate(registrationId, { status: 'confirmed' });
          console.log(`✅  Tryout registration confirmed — registrationId=${registrationId}`);
        } catch (dbErr) {
          console.error('❌  Failed to confirm tryout registration:', dbErr.message);
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
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
tryoutRegistrationSchema.index({ coach_id: 1 });

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

// ── MODELS ────────────────────────────────────────────────────────
const Coach              = mongoose.model('Coach',              coachSchema);
const Tryout             = mongoose.model('Tryout',             tryoutSchema);
const TryoutRegistration = mongoose.model('TryoutRegistration', tryoutRegistrationSchema);
const Player             = mongoose.model('Player',             playerSchema);
const Schedule           = mongoose.model('Schedule',           scheduleSchema);
const TeamFinancials     = mongoose.model('TeamFinancials',     teamFinancialsSchema);
const PlayerPayment      = mongoose.model('PlayerPayment',      playerPaymentSchema);
const Budget             = mongoose.model('Budget',             budgetSchema);

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

app.post('/api/checkout', async (req, res) => {
  if (!stripe) return res.status(500).json({ message: 'Stripe is not configured on the server' });

  try {
    const { coachId, paymentType, playerPaymentId, successUrl, cancelUrl } = req.body;
    if (!coachId || !paymentType || !playerPaymentId) {
      return res.status(400).json({ message: 'coachId, paymentType, and playerPaymentId are required' });
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
      metadata: {
        playerPaymentId,
        paymentType,
        coachId,
        ...(paymentType === 'installment' ? {
          paymentDeadline: financials.payment_deadline || '',
          totalMonths:     String(req._installmentTotalMonths || 0),
          remainderCents:  String(req._installmentRemainderCents || 0),
        } : {}),
      },
    };

    // For installments: store playerPaymentId on the subscription itself
    // so the customer.subscription.deleted webhook can link back to the player
    if (paymentType === 'installment') {
      sessionParams.subscription_data = {
        metadata: {
          playerPaymentId,
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
    });

    // ── If paid, create Stripe checkout and return URL ────────
    if (isPaid && stripe) {
      try {
        const session = await stripe.checkout.sessions.create({
          mode:        'payment',
          line_items:  [{ price: tryout.stripe_price_id, quantity: 1 }],
          success_url: successUrl || `${req.headers.origin || ''}?tryout_payment=success`,
          cancel_url:  cancelUrl  || `${req.headers.origin || ''}?tryout_payment=cancelled`,
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

    res.status(201).json({ message: 'Registration submitted', registration: reg, ghl: ghlResult });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── START SERVER ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`🚀  Server running on port ${PORT}`);
});
