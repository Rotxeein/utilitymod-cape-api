/**
 * UtilityMod Cape API Server v2
 * 
 * REST API to share capes (static + animated) between UtilityMod users.
 * Secured with HMAC-SHA256 signing + rate limiting.
 * 
 * Supported formats: PNG, JPG, GIF (animated), MP4 (converted to GIF)
 * 
 * Endpoints:
 *   POST   /api/cape/:uuid  — Upload cape (HMAC required)
 *   GET    /api/cape/:uuid  — Download cape (public)
 *   HEAD   /api/cape/:uuid  — Check cape existence (public)
 *   DELETE /api/cape/:uuid  — Remove cape (HMAC required)
 */

const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');

// ffmpeg setup — bundled via @ffmpeg-installer/ffmpeg
let ffmpegPath;
try {
    ffmpegPath = require('@ffmpeg-installer/ffmpeg').path;
} catch (e) {
    // Fallback to system ffmpeg
    ffmpegPath = 'ffmpeg';
}
let ffprobePath;
try {
    ffprobePath = require('@ffmpeg-installer/ffmpeg').path.replace('ffmpeg', 'ffprobe');
} catch (e) {
    ffprobePath = 'ffprobe';
}

const app = express();
const PORT = process.env.PORT || 3000;

// HMAC secret key — must match the key embedded in the mod
const HMAC_SECRET = process.env.HMAC_SECRET || 'UtilityMod-Cape-HMAC-Secret-2024-v1';
const TIMESTAMP_MAX_AGE_MS = 120_000; // 2 minutes
const MAX_VIDEO_DURATION = 5; // seconds
const MAX_GIF_FRAMES = 50;

// Storage directory for capes
const CAPES_DIR = path.join(__dirname, 'capes');
const TEMP_DIR = path.join(__dirname, 'temp');
if (!fs.existsSync(CAPES_DIR)) fs.mkdirSync(CAPES_DIR, { recursive: true });
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });

// ---- Rate Limiting ----
const rateLimits = new Map();
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 30;
const RATE_LIMIT_MAX_UPLOADS = 5;

function rateLimit(maxRequests) {
    return (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress;
        const key = `${ip}:${maxRequests}`;
        const now = Date.now();
        let entry = rateLimits.get(key);
        if (!entry || now > entry.resetTime) {
            entry = { count: 0, resetTime: now + RATE_LIMIT_WINDOW_MS };
            rateLimits.set(key, entry);
        }
        entry.count++;
        if (entry.count > maxRequests) {
            return res.status(429).json({ error: 'Too many requests. Try again later.' });
        }
        next();
    };
}

setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of rateLimits) {
        if (now > entry.resetTime) rateLimits.delete(key);
    }
}, 300_000);

// ---- HMAC Verification ----
function verifyHmac(req, res, next) {
    const signature = req.headers['x-signature'];
    const timestamp = req.headers['x-timestamp'];
    const uuid = req.params.uuid;

    if (!signature || !timestamp) {
        return res.status(401).json({ error: 'Missing authentication headers' });
    }

    const ts = parseInt(timestamp, 10);
    if (isNaN(ts) || Math.abs(Date.now() - ts) > TIMESTAMP_MAX_AGE_MS) {
        return res.status(401).json({ error: 'Request expired or invalid timestamp' });
    }

    const message = uuid.toLowerCase() + timestamp;
    const expected = crypto.createHmac('sha256', HMAC_SECRET).update(message).digest('hex');

    try {
        if (!crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'))) {
            return res.status(401).json({ error: 'Invalid signature' });
        }
    } catch (e) {
        return res.status(401).json({ error: 'Invalid signature format' });
    }

    next();
}

// UUID validation
function validateUuid(req, res, next) {
    const uuid = req.params.uuid;
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(uuid)) {
        return res.status(400).json({ error: 'Invalid UUID format' });
    }
    next();
}

// Multer: accept images + videos to temp, then process
const tempStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, TEMP_DIR),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase() || '.bin';
        cb(null, `upload_${Date.now()}_${Math.random().toString(36).slice(2)}${ext}`);
    }
});

const upload = multer({
    storage: tempStorage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
    fileFilter: (req, file, cb) => {
        const allowed = ['image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'video/mp4'];
        cb(null, allowed.includes(file.mimetype));
    }
});

/**
 * Get video/gif duration using ffprobe
 */
function getMediaDuration(filePath) {
    try {
        const result = execSync(
            `"${ffmpegPath}" -i "${filePath}" -f null - 2>&1`,
            { encoding: 'utf8', timeout: 10000 }
        ).toString();
        // Parse duration from ffmpeg output
        const match = result.match(/Duration:\s*(\d+):(\d+):(\d+)\.(\d+)/);
        if (match) {
            return parseInt(match[1]) * 3600 + parseInt(match[2]) * 60 + parseInt(match[3]) + parseInt(match[4]) / 100;
        }
    } catch (e) {
        // ffmpeg outputs to stderr, which causes execSync to throw
        const output = e.stderr ? e.stderr.toString() : (e.stdout ? e.stdout.toString() : '');
        const match = output.match(/Duration:\s*(\d+):(\d+):(\d+)\.(\d+)/);
        if (match) {
            return parseInt(match[1]) * 3600 + parseInt(match[2]) * 60 + parseInt(match[3]) + parseInt(match[4]) / 100;
        }
    }
    return -1;
}

/**
 * Convert MP4 to GIF using ffmpeg
 */
function convertMp4ToGif(inputPath, outputPath) {
    try {
        execSync(
            `"${ffmpegPath}" -y -i "${inputPath}" -t ${MAX_VIDEO_DURATION} -vf "fps=10,scale=64:-1:flags=lanczos" -loop 0 "${outputPath}"`,
            { timeout: 30000 }
        );
        return true;
    } catch (e) {
        console.error('[FFMPEG] Conversion failed:', e.message);
        return false;
    }
}

/**
 * Process uploaded file: validate duration, convert if needed, move to capes dir
 */
function processUpload(tempPath, mimetype, uuid) {
    const uuidClean = uuid.toLowerCase().replace(/[^a-f0-9\-]/g, '');
    
    if (mimetype === 'video/mp4') {
        // Check duration
        const duration = getMediaDuration(tempPath);
        if (duration > MAX_VIDEO_DURATION) {
            fs.unlinkSync(tempPath);
            return { error: `Video too long (${duration.toFixed(1)}s). Maximum is ${MAX_VIDEO_DURATION}s.` };
        }
        
        // Convert to GIF
        const gifPath = path.join(CAPES_DIR, uuidClean + '.gif');
        if (!convertMp4ToGif(tempPath, gifPath)) {
            fs.unlinkSync(tempPath);
            return { error: 'Failed to convert video to GIF' };
        }
        
        // Remove old PNG if exists, and temp file
        const pngPath = path.join(CAPES_DIR, uuidClean + '.png');
        if (fs.existsSync(pngPath)) fs.unlinkSync(pngPath);
        fs.unlinkSync(tempPath);
        
        return { success: true, type: 'gif', converted: true };
        
    } else if (mimetype === 'image/gif') {
        // Check duration of GIF
        const duration = getMediaDuration(tempPath);
        if (duration > MAX_VIDEO_DURATION && duration !== -1) {
            fs.unlinkSync(tempPath);
            return { error: `GIF too long (${duration.toFixed(1)}s). Maximum is ${MAX_VIDEO_DURATION}s.` };
        }
        
        // Move GIF to capes dir
        const gifPath = path.join(CAPES_DIR, uuidClean + '.gif');
        fs.renameSync(tempPath, gifPath);
        
        // Remove old PNG if exists
        const pngPath = path.join(CAPES_DIR, uuidClean + '.png');
        if (fs.existsSync(pngPath)) fs.unlinkSync(pngPath);
        
        return { success: true, type: 'gif' };
        
    } else {
        // Static image (PNG/JPG) — move directly
        const pngPath = path.join(CAPES_DIR, uuidClean + '.png');
        fs.renameSync(tempPath, pngPath);
        
        // Remove old GIF if exists
        const gifPath = path.join(CAPES_DIR, uuidClean + '.gif');
        if (fs.existsSync(gifPath)) fs.unlinkSync(gifPath);
        
        return { success: true, type: 'png' };
    }
}

/**
 * Find cape file (could be .png or .gif)
 */
function findCapeFile(uuid) {
    const uuidClean = uuid.toLowerCase();
    const gifPath = path.join(CAPES_DIR, uuidClean + '.gif');
    if (fs.existsSync(gifPath)) return { path: gifPath, type: 'image/gif' };
    const pngPath = path.join(CAPES_DIR, uuidClean + '.png');
    if (fs.existsSync(pngPath)) return { path: pngPath, type: 'image/png' };
    return null;
}

// ---- Routes ----

// POST /api/cape/:uuid — Upload cape (HMAC protected)
app.post('/api/cape/:uuid', validateUuid, rateLimit(RATE_LIMIT_MAX_UPLOADS), verifyHmac, upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file provided' });
    }
    
    const result = processUpload(req.file.path, req.file.mimetype, req.params.uuid);
    if (result.error) {
        return res.status(400).json({ error: result.error });
    }
    
    console.log(`[UPLOAD] Cape uploaded for ${req.params.uuid} (${result.type}${result.converted ? ', converted from MP4' : ''}) from ${req.ip}`);
    res.status(201).json({ success: true, uuid: req.params.uuid, type: result.type });
});

// GET /api/cape/:uuid — Download cape (public)
app.get('/api/cape/:uuid', validateUuid, rateLimit(RATE_LIMIT_MAX_REQUESTS), (req, res) => {
    const cape = findCapeFile(req.params.uuid);
    if (!cape) {
        return res.status(404).json({ error: 'Cape not found' });
    }
    
    res.setHeader('Content-Type', cape.type);
    res.setHeader('Cache-Control', 'public, max-age=60');
    res.sendFile(cape.path);
});

// HEAD /api/cape/:uuid — Check cape existence (public)
app.head('/api/cape/:uuid', validateUuid, rateLimit(RATE_LIMIT_MAX_REQUESTS), (req, res) => {
    const cape = findCapeFile(req.params.uuid);
    if (!cape) {
        return res.status(404).end();
    }
    
    const stats = fs.statSync(cape.path);
    res.setHeader('Content-Length', stats.size);
    res.setHeader('Content-Type', cape.type);
    res.status(200).end();
});

// DELETE /api/cape/:uuid — Remove cape (HMAC protected)
app.delete('/api/cape/:uuid', validateUuid, rateLimit(RATE_LIMIT_MAX_UPLOADS), verifyHmac, (req, res) => {
    const uuid = req.params.uuid.toLowerCase();
    let deleted = false;
    
    const pngPath = path.join(CAPES_DIR, uuid + '.png');
    if (fs.existsSync(pngPath)) { fs.unlinkSync(pngPath); deleted = true; }
    
    const gifPath = path.join(CAPES_DIR, uuid + '.gif');
    if (fs.existsSync(gifPath)) { fs.unlinkSync(gifPath); deleted = true; }
    
    if (deleted) console.log(`[DELETE] Cape removed for ${uuid} from ${req.ip}`);
    res.json({ success: true });
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        capes: fs.readdirSync(CAPES_DIR).filter(f => f.endsWith('.png') || f.endsWith('.gif')).length,
        ffmpeg: ffmpegPath
    });
});

app.listen(PORT, () => {
    console.log(`UtilityMod Cape API v2 running on port ${PORT}`);
    console.log(`Capes directory: ${CAPES_DIR}`);
    console.log(`HMAC protection: ENABLED`);
    console.log(`FFmpeg path: ${ffmpegPath}`);
    console.log(`Max video duration: ${MAX_VIDEO_DURATION}s`);
});
