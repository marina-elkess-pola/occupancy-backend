const { MongoClient } = require("mongodb");
let client, db;

async function getDb() {
  if (!db) {
    const uri = process.env.MONGODB_URI;
    if (!uri) throw new Error("MONGODB_URI not set in .env");
    client = new MongoClient(uri, { serverSelectionTimeoutMS: 10000, maxPoolSize: 10 });
    await client.connect();
    db = client.db("occupancy");
    console.log("✅ Mongo connected");
  }
  return db;
}
module.exports = { getDb };
