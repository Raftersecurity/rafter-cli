// Application config — INTENTIONAL FAKE SECRETS for fixture testing

const GOOGLE_KEY = "AIzaFAKE-NOTREAL123456789abcdefghijklmn";
const GOOGLE_OAUTH = "123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com";

// Twilio
const TWILIO_KEY = "SKFAKE0123456789abcdef0123456789ab";

// Generic patterns
const api_key = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6';
const secret = 'xK9mP2vL5nQ8wR3jB7cF0hT6yU1aD4eG';

// JWT
const SESSION_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidGVzdCI6InRydWUiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// Custom internal token (matches .rafter.yml custom_patterns)
const INTERNAL_SVC = "SVC_TOKEN_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6";

module.exports = { GOOGLE_KEY, TWILIO_KEY };
