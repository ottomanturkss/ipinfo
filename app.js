const express = require('express');
const axios = require('axios');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');
const tls = require('tls');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const bodyParser = require('body-parser');

const app = express();

// Updated port and host configuration
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';  // Allow connections from all network interfaces

// Set up EJS as view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Common ports to scan
const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443];

// HTTPS/TLS ports to check for certificates
const TLS_PORTS = [443, 465, 587, 993, 995, 8443];

// Known blacklists to check
const BLACKLISTS = [
  'zen.spamhaus.org',
  'bl.spamcop.net',
  'b.barracudacentral.org',
  'dnsbl.sorbs.net'
];

// Port to service name mapping
function getServiceName(port) {
  const services = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    465: 'SMTPS',
    587: 'Submission',
    993: 'IMAPS',
    995: 'POP3S',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt'
  };
  return services[port] || 'Unknown';
}

// Function to check if a port is open
async function isPortOpen(host, port, timeout = 1000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let status = false;
    let error = null;

    // Timeout if it takes too long to connect
    socket.setTimeout(timeout);

    // Handle successful connection
    socket.on('connect', () => {
      status = true;
      socket.destroy();
    });

    // Handle timeout and error
    socket.on('timeout', () => {
      socket.destroy();
    });
    
    socket.on('error', (err) => {
      error = err.message;
      socket.destroy();
    });

    // Resolve promise when socket is closed
    socket.on('close', () => {
      resolve({ port, open: status, error });
    });

    // Attempt connection
    socket.connect(port, host);
  });
}

// Function to perform reverse DNS lookup
async function performReverseDNS(ip) {
  try {
    const hostnames = await dns.reverse(ip);
    return hostnames;
  } catch (error) {
    console.error('Reverse DNS lookup error:', error.message);
    return ['No hostname found or error in lookup'];
  }
}

// Function to retrieve TLS/SSL certificate information
async function getCertificateInfo(host, port = 443) {
  return new Promise((resolve) => {
    try {
      const socket = tls.connect(
        {
          host,
          port,
          rejectUnauthorized: false, // Allow self-signed or invalid certs
          servername: host, // Enable SNI
          timeout: 5000
        },
        () => {
          const cert = socket.getPeerCertificate(true);
          const sni = socket.servername ? true : false;
          
          // Format the certificate data
          const certInfo = {
            commonName: cert.subject?.CN || 'Unknown',
            organization: cert.subject?.O || 'Unknown',
            issuer: cert.issuer?.CN || 'Unknown',
            validFrom: cert.valid_from || 'Unknown',
            validTo: cert.valid_to || 'Unknown',
            serialNumber: cert.serialNumber || 'Unknown',
            sniSupported: sni,
            altNames: cert.subjectaltname ? 
              cert.subjectaltname.split(', ').map(name => name.replace('DNS:', '')) : 
              []
          };
          
          socket.end();
          resolve({ success: true, data: certInfo });
        }
      );

      socket.on('error', (error) => {
        console.error(`Certificate error for ${host}:${port}:`, error.message);
        socket.destroy();
        resolve({ success: false, error: error.message });
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve({ success: false, error: 'Connection timeout' });
      });
    } catch (error) {
      console.error(`General certificate error for ${host}:${port}:`, error.message);
      resolve({ success: false, error: error.message });
    }
  });
}

// Function to check if IP is in blacklists
async function checkBlacklists(ip) {
  const results = [];
  const reversedIp = ip.split('.').reverse().join('.');

  for (const blacklist of BLACKLISTS) {
    try {
      const lookupDomain = `${reversedIp}.${blacklist}`;
      await dns.resolve(lookupDomain);
      results.push({ list: blacklist, listed: true });
    } catch (error) {
      // IP not found in blacklist (expected)
      results.push({ list: blacklist, listed: false });
    }
  }
  
  return results;
}

// Function to check if IP is a Tor exit node
async function checkTorNode(ip) {
  try {
    const response = await axios.get(`https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1`);
    const torExitNodes = response.data.split('\n').filter(line => !line.startsWith('#') && line.trim() !== '');
    return torExitNodes.includes(ip);
  } catch (error) {
    console.error('Error checking Tor status:', error.message);
    return false;
  }
}

// Function to perform a traceroute
async function performTraceroute(ip) {
  try {
    // Different command based on OS
    const isWindows = process.platform === 'win32';
    const command = isWindows ? 
      `tracert -d -h 15 -w 1000 ${ip}` : 
      `traceroute -n -w 1 -q 1 -m 15 ${ip}`;
    
    try {
      const { stdout, stderr } = await execPromise(command, { timeout: 20000 });
      if (stderr) console.error('Traceroute stderr:', stderr);
      
      // Parse traceroute output
      const lines = stdout.split('\n').filter(line => 
        line.trim() !== '' && 
        !line.includes('traceroute to') && 
        !line.includes('Tracing route') &&
        !line.includes('over a maximum')
      );
      
      // Extract hop information
      return lines.map(line => {
        // For Windows format
        if (isWindows) {
          const match = line.match(/\s*(\d+)\s+(?:(<?\s*\d+\s*ms)|(\*))\s+(?:(<?\s*\d+\s*ms)|(\*))\s+(?:(<?\s*\d+\s*ms)|(\*))\s+(.+)?/);
          if (match) {
            const hop = match[1];
            const times = [match[2], match[4], match[6]].filter(t => t && !t.includes('*')).map(t => parseInt(t));
            const avgTime = times.length > 0 ? times.reduce((a, b) => a + b, 0) / times.length : null;
            const ip = match[8]?.trim() || 'Timeout';
            return { hop, ip, time: avgTime ? `${avgTime} ms` : 'Timeout' };
          }
        } else {
          // For Unix format
          const parts = line.trim().split(/\s+/);
          const hop = parts[0].replace(':', '');
          const ip = parts[1] === '*' ? 'Timeout' : parts[1];
          const time = parts[2] === '*' ? 'Timeout' : parts[2];
          return { hop, ip, time };
        }
        return null;
      }).filter(hop => hop !== null);
    } catch (error) {
      console.error('Traceroute execution error:', error.message);
      
      // Return a simulated traceroute with error indication
      return [
        { hop: '1', ip: 'Local Router', time: '< 5 ms' },
        { hop: '2', ip: 'Internet Service Provider', time: '~10-30 ms' },
        { hop: '3', ip: '...', time: '...' },
        { hop: 'X', ip: `${ip} (Destination)`, time: 'Command Execution Failed' },
        { hop: 'Note', ip: 'Traceroute requires elevated permissions', time: error.message.substring(0, 30) + '...' }
      ];
    }
  } catch (generalError) {
    console.error('Traceroute general error:', generalError.message);
    
    // Return a generic error state
    return [{ 
      hop: 'Error', 
      ip: 'Traceroute functionality is not available', 
      time: 'Command execution failed. This typically requires administrative privileges.' 
    }];
  }
}

// Function to measure latency (ping)
async function measureLatency(ip) {
  try {
    const isWindows = process.platform === 'win32';
    const command = isWindows ? 
      `ping -n 4 ${ip}` : 
      `ping -c 4 ${ip}`;
    
    try {
      const { stdout, stderr } = await execPromise(command, { timeout: 10000 });
      if (stderr) console.error('Ping stderr:', stderr);
      
      // Extract average ping time
      const avgMatch = stdout.match(/(Average|average) = (\d+)ms/) || 
                      stdout.match(/(\d+\.\d+)\/(\d+\.\d+)\/(\d+\.\d+)\/(\d+\.\d+)/);
      
      if (avgMatch) {
        return isWindows ? `${avgMatch[2]} ms` : `${avgMatch[2]} ms`;
      } else {
        return 'Unable to determine';
      }
    } catch (error) {
      console.error('Ping execution error:', error.message);
      return 'Estimated: 50-200 ms';
    }
  } catch (error) {
    console.error('Ping general error:', error.message);
    return 'Not available (requires privileges)';
  }
}

// Routes
app.get('/', (req, res) => {
  res.render('index', { ipData: null, error: null });
});

app.get('/privacy', (req, res) => {
  res.render('privacy');
});

app.post('/lookup', async (req, res) => {
  try {
    const { ipAddress } = req.body;
    
    // Basic IP validation
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$|^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
    if (!ipRegex.test(ipAddress)) {
      throw new Error('Invalid IP address or domain format');
    }

    // Get IP information from ip-api.com
    const ipApiResponse = await axios.get(`http://ip-api.com/json/${ipAddress}`);
    const ipApiData = ipApiResponse.data;

    if (ipApiData.status === 'fail') {
      throw new Error('Failed to get IP information');
    }

    // Get additional information from ipinfo.io (if you have a token)
    // const ipInfoResponse = await axios.get(`https://ipinfo.io/${ipAddress}/json?token=YOUR_TOKEN`);
    // const ipInfoData = ipInfoResponse.data;

    const ipData = {
      ip: ipAddress,
      ipApi: ipApiData,
      ipInfo: {}, // Add ipinfo.io data here if you have a token
      network: {
        latency: 'N/A' // Add actual latency check if needed
      },
      isTorNode: false, // Add Tor exit node check if needed
      ports: [], // Add port scanning if needed
      hostnames: [], // Add DNS lookup if needed
      blacklists: [], // Add blacklist checking if needed
      whois: {}, // Add WHOIS lookup if needed
      certificates: [], // Add SSL cert checking if needed
      geo: {
        latitude: ipApiData.lat,
        longitude: ipApiData.lon,
        country: ipApiData.country,
        region: ipApiData.regionName,
        city: ipApiData.city
      }
    };

    res.render('index', { ipData, error: null });
  } catch (error) {
    res.render('index', { 
      ipData: null, 
      error: error.message || 'An error occurred while looking up IP information' 
    });
  }
});

// Helper function for port service names
app.locals.getServiceName = (port) => {
  const commonPorts = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    27017: 'MongoDB'
  };
  return commonPorts[port] || 'Unknown';
};

// Basic health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server with updated configuration
app.listen(PORT, HOST, () => {
  console.log(`Server is running on http://${HOST}:${PORT}`);
  console.log('Environment:', process.env.NODE_ENV || 'development');
}); 