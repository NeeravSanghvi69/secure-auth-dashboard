# Use official Node.js LTS image
FROM node:18-alpine

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy app source
COPY . .

# Expose backend port
EXPOSE 3000

# Start server
CMD ["node", "app.js"]
