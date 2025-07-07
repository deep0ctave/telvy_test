# Use official Node image
FROM node:18

# Set working directory
WORKDIR /app

# Copy only package files first for caching
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the code
COPY . .

# Expose the Vite port
EXPOSE 5173

# Default command overridden by docker-compose
CMD ["npm", "run", "dev"]
