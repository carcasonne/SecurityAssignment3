<<<<<<< HEAD
# Use the latest nginx base image
=======
                               # Use the latest nginx base image
>>>>>>> 106878b0bdbbab2cc4d6f896dd3e59e5ae5bd855
FROM nginx:latest

# Remove the default config folder from nginx
RUN rm /etc/nginx/conf.d/default.conf

# Move our own config folder in
COPY nginx.conf /etc/nginx/conf.d/

CMD ["nginx", "-g", "'daemon off;'"]