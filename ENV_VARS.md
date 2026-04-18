
# Required environment variables for Render

Set these in the Render service dashboard (Environment → Environment Variables).

- MONGODB_URI
  - Example: `mongodb+srv://myuser:password@cluster0.mongodb.net/occupancy?retryWrites=true&w=majority`
- EMAIL_USER
  - Example: `noreply@yourdomain.com`
- EMAIL_PASS
  - Example: `app-specific-password-or-smtp-password` (do NOT paste the real secret here)
- JWT_SECRET
  - Example: a long random string used to sign JWT tokens, e.g. `somerandomlongsecret123!`
- ANTHROPIC_API_KEY
  - Required for BSI AI features (auto-classify, design advisor)
  - Get from https://console.anthropic.com/settings/keys

Port: the app uses `process.env.PORT` or defaults to 5050. Render will set its own `$PORT` automatically.
