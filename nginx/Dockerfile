# Use the official Nginx image
FROM nginx:alpine

# Remove the default Nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Copy our custom config
COPY nginx.conf /etc/nginx/nginx.conf

# Run Nginx in foreground
CMD ["nginx", "-g", "daemon off;"]
