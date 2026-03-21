# Stage 1: Build the React application
FROM node:18-alpine as builder

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# Build the app to the 'dist' folder
RUN npm run build

# Stage 2: Serve the app with Nginx
FROM nginx:alpine

# Copy the built assets to Nginx's html folder
COPY --from=builder /app/dist /usr/share/nginx/html

# Expose port (default for Nginx is 80)
EXPOSE 80

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]
