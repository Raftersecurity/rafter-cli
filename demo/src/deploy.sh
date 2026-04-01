#!/bin/bash
# Demo deployment script — shows commands rafter would intercept

# Low risk — would be allowed
npm install
npm run build

# Medium risk — would require approval on moderate+
sudo systemctl restart nginx
chmod 755 /var/www/app

# High risk — would require approval
npm publish
git push --force origin main

# Critical — would be BLOCKED
rm -rf /
dd if=/dev/zero of=/dev/sda
:(){ :|:& };:
