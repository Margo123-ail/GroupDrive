// GroupDrive creates and migrates its SQLite schema from server.js on startup.
// This file is kept as a small helper/reference for the project structure.
const path = require('path');
const fs = require('fs');
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
module.exports = { databasePath: path.join(dataDir, 'groupdrive.db') };
