#!/bin/bash

# Install dependencies
npm install

# Set environment variables
export NODE_ENV=production
export PORT=${PORT:-3000}
export HOST=${HOST:-0.0.0.0}

# Start the application with increased memory limits
node --max-old-space-size=512 --max-semi-space-size=256 app.js 