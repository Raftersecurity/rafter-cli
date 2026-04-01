// Demo app configuration — INTENTIONAL FAKE SECRETS for rafter demo

const config = {
  database: {
    host: "db.internal",
    port: 5432,
    password: "supersecret123",
  },
  aws: {
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region: "us-east-1",
  },
  stripe: {
    secretKey: "sk_test_51OaJQLBjKV8F0MXxEXAMPLEKEY00",
  },
  jwt: {
    secret: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRlbW8iLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  },
  slack: {
    webhook: "https://hooks.slack.example/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
  },
};

module.exports = config;
