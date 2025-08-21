require('dotenv').config();
const express = require('express');
const axios = require('axios');
const mongoose = require('mongoose');
const crypto = require('crypto');
const bodyParser = require('body-parser');

const app = express();

// *** Use environment variable for port, crucial for Render
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: (req, res, buf) => { req.rawBody = buf } })); // *** Needed for webhook verification
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// --- MongoDB Setup ---
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log("MongoDB Connection Error: ", err));

// *** Added indexes for performance
const merchantSchema = new mongoose.Schema({
  shopDomain: { type: String, index: true, unique: true },
  accessToken: String
});
const chargeSchema = new mongoose.Schema({
  shopDomain: { type: String, index: true },
  orderId: String,
  amount: Number,
  fee: Number,
  timestamp: { type: Date, default: Date.now }
});
const Merchant = mongoose.model('Merchant', merchantSchema);
const Charge = mongoose.model('Charge', chargeSchema);

// --- CORRECT Coinbase Webhook Signature Verification ---
// *** This is the official method from Coinbase docs
function verifyCoinbaseSignature(req, secret) {
  const signature = req.headers['x-cc-webhook-signature'];
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(req.rawBody);
  const computedSignature = hmac.digest('hex');
  return computedSignature === signature;
}

// --- Shopify OAuth ---
app.get('/auth', (req, res) => {
  const { shop } = req.query;
  
  // *** Use environment variable for dynamic redirect. This fixes the critical bug.
  const redirect_uri = `${process.env.APP_URL}/auth/callback`;
  
  const authURL = `https://${shop}/admin/oauth/authorize?client_id=${process.env.SHOPIFY_CLIENT_ID}&scope=write_orders,read_orders&redirect_uri=${redirect_uri}`;
  res.redirect(authURL);
});

app.get('/auth/callback', async (req, res) => {
  const { shop, code } = req.query;
  
  // *** Basic validation
  if (!shop || !code) {
    return res.status(400).send('Missing parameters');
  }

  try {
    const response = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: process.env.SHOPIFY_CLIENT_ID,
      client_secret: process.env.SHOPIFY_CLIENT_SECRET,
      code
    });
    const { access_token } = response.data;
    
    await Merchant.findOneAndUpdate(
      { shopDomain: shop }, 
      { accessToken: access_token }, 
      { upsert: true, new: true }
    );
    
    res.redirect(`/dashboard?shop=${shop}`);
  } catch (err) {
    console.error('OAuth Error:', err.response?.data || err.message);
    res.status(500).render('error', { message: 'Installation failed. Please try again.' });
  }
});

// --- Merchant Dashboard ---
app.get('/dashboard', async (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).send('Shop parameter required');

  try {
    const merchant = await Merchant.findOne({ shopDomain: shop });
    if (!merchant) return res.redirect(`/auth?shop=${shop}`); // *** Auto-start install if not found

    const charges = await Charge.find({ shopDomain: shop }).sort({ timestamp: -1 }).limit(10);
    const totalRevenue = charges.reduce((acc, c) => acc + c.amount, 0);
    const totalFees = charges.reduce((acc, c) => acc + c.fee, 0);

    res.render('dashboard', { 
      shopDomain: shop, 
      charges, 
      totalRevenue: totalRevenue.toFixed(2), 
      totalFees: totalFees.toFixed(2) 
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

// --- Create Coinbase Charge ---
app.post('/create-charge', async (req, res) => {
  const { orderId, amount, shopDomain } = req.body;
  
  // *** Basic input validation
  if (!orderId || !amount || !shopDomain) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const feeAmount = (amount * 0.01).toFixed(2); // *** Your 1% fee

  try {
    const chargeData = {
      name: `Order #${orderId}`,
      description: `Payment for Shopify order #${orderId}`,
      pricing_type: 'fixed_price',
      local_price: { 
        amount: amount.toString(), // *** Coinbase expects string amounts
        currency: 'USD' 
      },
      metadata: { 
        shopify_order_id: orderId, 
        shop_domain: shopDomain 
      },
      redirect_url: `https://${shopDomain}/orders/${orderId}`, // *** Better URL
      cancel_url: `https://${shopDomain}/cart`,
    };

    // *** Only add recipient if fee is greater than 0
    if (feeAmount > 0) {
      chargeData.additional_recipients = [{
        type: 'crypto_receiver', 
        address: process.env.RIVERXPAY_WALLET, 
        amount: feeAmount
      }];
    }

    const response = await axios.post(
      'https://api.commerce.coinbase.com/charges',
      chargeData,
      { 
        headers: { 
          'X-CC-Api-Key': process.env.COINBASE_API_KEY, 
          'X-CC-Version': '2018-03-22', 
          'Content-Type': 'application/json' 
        } 
      }
    );

    // Save charge in MongoDB for analytics
    await Charge.create({ 
      shopDomain, 
      orderId, 
      amount: parseFloat(amount), 
      fee: parseFloat(feeAmount) 
    });

    res.json({ checkout_url: response.data.data.hosted_url });

  } catch (err) {
    console.error('Charge Creation Error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to create payment link' });
  }
});

// --- Coinbase Webhook ---
app.post('/webhook', async (req, res) => {
  // *** Use the corrected verification function
  if (!verifyCoinbaseSignature(req, process.env.COINBASE_WEBHOOK_SECRET)) {
    console.error('Webhook signature invalid');
    return res.status(401).send('Invalid signature');
  }

  const event = req.body.event;
  console.log(`Received webhook event: ${event.type}`);

  // *** Only process confirmed charges
  if (event.type === 'charge:confirmed') {
    try {
      const { shopify_order_id, shop_domain } = event.data.metadata;
      const amount = event.data.pricing.local.amount;

      if (!shopify_order_id || !shop_domain) {
        throw new Error('Missing metadata in webhook');
      }

      const merchant = await Merchant.findOne({ shopDomain: shop_domain });
      if (!merchant) {
        throw new Error(`Merchant not found for shop: ${shop_domain}`);
      }

      // *** CORRECT Shopify API call to create a transaction
      // Using a stable API version like '2024-01'
      const shopifyResponse = await axios.post(
        `https://${shop_domain}/admin/api/2024-01/orders/${shopify_order_id}/transactions.json`,
        {
          transaction: {
            kind: 'capture',
            status: 'success',
            amount: amount,
            currency: 'USD'
          }
        },
        {
          headers: {
            'X-Shopify-Access-Token': merchant.accessToken,
            'Content-Type': 'application/json'
          }
        }
      );

      console.log(`Order ${shopify_order_id} marked as paid in ${shop_domain}`);
      
    } catch (err) {
      // *** Don't return 500 to Coinbase or they might disable the webhook
      // Log the error extensively for debugging
      console.error('Webhook Processing Error:', err.response?.data || err.message);
    }
  }

  res.status(200).send('Webhook received');
});

const path = require('path');

// Basic Home Page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html')); // Make sure index.html is in the same folder
});

// --- Start Server ---
app.listen(PORT, () => console.log(`RiverXPay running on port ${PORT}`));
