/**
 * UtilityMod Cape API Server
 * 
 * Simple REST API to share capes between UtilityMod users.
 * 
 * Endpoints:
 *   POST   /api/cape/:uuid  — Upload cape (multipart/form-data, field "image")
 *   GET    /api/cape/:uuid  — Download cape image
 *   DELETE /api/cape/:uuid  — Remove cape
 * 
 * Setup:
 *   1. npm install express multer
 *   2. node server.js
 *   3. Set the API URL in: %USERPROFILE%/utilitymod/api-url.txt
 * 
 * For production, deploy on Railway, Render, or a VPS.
 */

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Storage directory for capes
const CAPES_DIR = path.join(__dirname, 'capes');
if (!fs.existsSync(CAPES_DIR)) {
    fs.mkdirSync(CAPES_DIR, { recursive: true });
}

// Multer config for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, CAPES_DIR),
    filename: (req, file, cb) => {
        const uuid = req.params.uuid.toLowerCase().replace(/[^a-f0-9\-]/g, '');
        cb(null, uuid + '.png');
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
    fileFilter: (req, file, cb) => {
        const allowed = ['image/png', 'image/jpeg', 'image/jpg'];
        cb(null, allowed.includes(file.mimetype));
    }
});

// UUID validation middleware
function validateUuid(req, res, next) {
    const uuid = req.params.uuid;
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(uuid)) {
        return res.status(400).json({ error: 'Invalid UUID format' });
    }
    next();
}

// POST /api/cape/:uuid — Upload cape
app.post('/api/cape/:uuid', validateUuid, upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No image file provided' });
    }
    console.log(`[UPLOAD] Cape uploaded for ${req.params.uuid}`);
    res.status(201).json({ success: true, uuid: req.params.uuid });
});

// GET /api/cape/:uuid — Download cape
app.get('/api/cape/:uuid', validateUuid, (req, res) => {
    const uuid = req.params.uuid.toLowerCase();
    const filePath = path.join(CAPES_DIR, uuid + '.png');

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'Cape not found' });
    }

    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Cache-Control', 'public, max-age=60');
    res.sendFile(filePath);
});

// DELETE /api/cape/:uuid — Remove cape
app.delete('/api/cape/:uuid', validateUuid, (req, res) => {
    const uuid = req.params.uuid.toLowerCase();
    const filePath = path.join(CAPES_DIR, uuid + '.png');

    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        console.log(`[DELETE] Cape removed for ${uuid}`);
    }

    res.json({ success: true });
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', capes: fs.readdirSync(CAPES_DIR).length });
});

app.listen(PORT, () => {
    console.log(`UtilityMod Cape API running on port ${PORT}`);
    console.log(`Capes directory: ${CAPES_DIR}`);
});
