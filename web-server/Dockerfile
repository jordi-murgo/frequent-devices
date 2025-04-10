FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy web-server application code
COPY . .

# Create frontend directory
RUN mkdir -p /usr/src/app/frontend

# Note: The frontend files will be mounted as a volume in docker-compose.yml
# or copied during the build process in the docker-compose context

# Expose the port the app runs on
EXPOSE 8080

# Command to run the application
CMD ["npm", "start"]
