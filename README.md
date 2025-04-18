# IP Information Lookup Tool

A web application that allows users to look up detailed information about IP addresses, including geolocation data and more.

## Features

- IP address validation
- Geolocation information
- Clean and responsive UI
- Modal display for detailed information

## Prerequisites

- Node.js (v14 or higher)
- npm (Node Package Manager)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ottomanturkss/ipinfo.git
   cd ipinfo
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

## Running the Application

### Development Mode
To run the application in development mode with auto-reload:
```bash
npm run dev
```

### Production Mode
To run the application in production mode:
```bash
npm start
```

The application will be available at `http://localhost:3000`

## Project Structure

```
ipinfo/
├── app.js              # Main Express server file
├── public/
│   ├── css/           # Stylesheets
│   └── js/            # Client-side JavaScript
└── views/             # EJS templates
```

## Technologies Used

- Express.js - Web application framework
- EJS - Templating engine
- Axios - HTTP client
- Body Parser - Request parsing middleware

## Dependencies

- Express.js - Web server framework
- Axios - HTTP client for API requests
- EJS - Templating engine for views
- Built-in Node.js modules (dns, net, tls, child_process) for advanced features

## Security Notes

- The port scanning feature only checks common ports and is meant for educational purposes
- For production use, consider adding rate limiting and additional security measures
- This tool should only be used ethically and legally for network diagnostics and information gathering

## Future Improvements

- Add packet analysis and TCP fingerprinting
- Implement full bandwidth testing
- Add historical IP reputation data
- Support for IP ranges and CIDR notation
- Add automatic domain discovery for the IP
- Additional customization options for scan intensity

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

- **Onur Altun** ([ottomanturkss](https://github.com/ottomanturkss))
- Last Updated: April 18, 2025 
