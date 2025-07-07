# Use Node.js base image
FROM node:18

# Set working directory
WORKDIR /app

# Copy dependency files and install packages
COPY package*.json ./
RUN npm install

# Copy rest of the app
COPY . .

# Expose backend port
EXPOSE 3000

# Run init-db first, then start the server
CMD ["sh", "-c", "npm run init-db && npm start"]
