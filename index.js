// Backend: Node.js (Express.js)
// To use: create a .env file with your API keys and run `npm install express axios dotenv`

process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';

const express = require('express');
const axios = require('axios');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
const PORT = 3000;

const VT_API_KEY='9930c8183e2329d36f86041ccef5a355f5818f94e60f1f0f2359c80f3e24968e';
const ABUSE_API_KEY='e79c4a87b60b4376810e33ca5586fa8a3698ae2b6abe686df99e697d3214501701b9b7aad9279079';
const IPQS_API_KEY='nOAPfz97uiVWm8xRMJapXRgEXE1q8cXD';
const VPNAPI_API_KEY='58e5f43df709497f82a990ffdbbfc253';
const SCAMALYTICS_USER='softwareone2';
const SCAMALYTICS_API_KEY='96a9a15ee75962baf7807eb1e0353aafb7ee1f76d238d8dff80a816b07fb0168';

app.use(express.static('public'));

app.get('/check-ip', async (req, res) => {
  const ip = req.query.ip;
  if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    return res.status(400).json({ error: 'Invalid IP address' });
  }

  try {
    const vt = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: { 'x-apikey': VT_API_KEY }
    });

    const abuse = await axios.get(`https://api.abuseipdb.com/api/v2/check`, {
      headers: { 'Key': ABUSE_API_KEY, 'Accept': 'application/json' },
      params: { ipAddress: ip }
    });

    const ipqs = await axios.get(`https://ipqualityscore.com/api/json/ip/${IPQS_API_KEY}/${ip}`);

    const vpnapi = await axios.get(`https://vpnapi.io/api/${ip}?key=${VPNAPI_API_KEY}`);

    const scam = await axios.get(`https://api12.scamalytics.com/v3/${SCAMALYTICS_USER}/?key=${SCAMALYTICS_API_KEY}&ip=${ip}`);

    res.json({
      virustotal: vt.data,
      abuseipdb: abuse.data,
      ipqualityscore: ipqs.data,
      vpnapiio: vpnapi.data,
      scamalytics: scam.data,
    });

  } catch (err) {
    console.error("Error details:", err.response?.data || err.message || err);
    res.status(500).json({ error: 'Error fetching data from one or more services' });
  }  
});

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});