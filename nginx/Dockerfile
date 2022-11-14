# Use the latest nginx base image
FROM nginx:latest

# Remove the default config folder from nginx
RUN rm /etc/nginx/conf.d/default.conf

# Move our own config folder in
COPY nginx.conf /etc/nginx/conf.d/

CMD ["nginx", "-g", "'daemon off;'"]