#!/bin/bash
# Deployment script — commands across all 4 risk tiers for interception testing

# LOW RISK — always allowed
npm install
npm run build
git status
ls -la

# MEDIUM RISK — contextual approval
sudo systemctl restart nginx
chmod 755 /var/www/app
docker run --rm myapp:latest

# HIGH RISK — requires approval
npm publish --access public
git push --force origin main
curl -X DELETE https://api.example.com/resources/all

# CRITICAL — always blocked
rm -rf /
dd if=/dev/zero of=/dev/sda
:(){ :|:& };:
