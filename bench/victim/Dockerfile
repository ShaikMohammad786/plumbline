FROM node:latest
USER root
ENV AWS_SECRET_ACCESS_KEY=AKIA1234567890EXAMPLE
RUN curl -sSL http://example.com/install.sh | bash
WORKDIR /app
COPY . .
RUN npm ci --only=production
EXPOSE 3000
CMD ["npm", "start"]
