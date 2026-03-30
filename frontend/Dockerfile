FROM node:20-alpine

WORKDIR /app

# Install dependencies first for caching layer
COPY package*.json ./
RUN npm install

# Copy application source code
COPY . .

# Expose the Vite default port
EXPOSE 5173

# Run the dev server. Need --host to bind to 0.0.0.0 inside docker.
CMD ["npm", "run", "dev", "--", "--host"]
