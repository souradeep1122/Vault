require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');


const app = express();
const router = express.Router();

// --- EJS & VIEW ENGINE ---
app.set('view engine', 'ejs');
app.set('views', path.join(process.cwd(), 'views'));

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// --- CONFIGURATION & PRE-FLIGHT ---
const MONGO_URI = process.env.MONGO_URI
    ? process.env.MONGO_URI.trim().replace(/\s/g, '').replace(/=true/gi, '=true')
    : null;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY
    ? process.env.ENCRYPTION_KEY.trim()
    : null;
const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;

if (!MONGO_URI || !ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 32) {
    console.error('FATAL ERROR: Check MONGO_URI and ENCRYPTION_KEY (must be 32 chars) in .env');
    process.exit(1);
}

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME?.trim(),
    api_key:    process.env.CLOUDINARY_API_KEY?.trim(),
    api_secret: process.env.CLOUDINARY_API_SECRET?.trim()
});

// --- ENCRYPTION HELPERS ---
function encrypt(text) {
    if (!text) return null;
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text || !text.includes(':')) return text;
    try {
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (err) {
        return "Decryption Error";
    }
}

// -------------------------------------------------------------------
// FIX 1: Correct public-ID extraction.
// Cloudinary URLs look like:
//   https://res.cloudinary.com/<cloud>/image/upload/v1234/vault_secure/abc.jpg
//   https://res.cloudinary.com/<cloud>/raw/upload/v1234/vault_secure/abc.pdf
// We need everything AFTER the version segment, WITHOUT the extension.
// -------------------------------------------------------------------
function getPublicIdFromUrl(url) {
    if (!url) return null;
    try {
        // Match everything after /upload/  (optionally skipping a version like v12345/)
        const match = url.match(/\/upload\/(?:v\d+\/)?(.+)$/);
        if (!match) return null;
        const withExt = match[1]; // e.g. "vault_secure/abc.pdf"
        // Strip the last extension only
        return withExt.replace(/\.[^/.]+$/, ''); // => "vault_secure/abc"
    } catch (e) {
        return null;
    }
}

// -------------------------------------------------------------------
// FIX 2: Determine the Cloudinary resource_type from a stored URL.
// PDFs are uploaded as resource_type:'raw', images as 'image'.
// Using the wrong type on destroy() silently fails.
// -------------------------------------------------------------------
function getResourceTypeFromUrl(url) {
    if (!url) return 'image';
    // Cloudinary embeds the resource type in the URL path segment
    if (url.includes('/raw/upload/'))   return 'raw';
    if (url.includes('/video/upload/')) return 'video';
    return 'image'; // default
}




// -------------------------------------------------------------------
// FIX 3: Cloudinary storage with explicit allowed formats + size limit.
// resource_type:'auto' tells Cloudinary to detect PDF vs image.
// file_size_limit (in bytes) prevents silent 413 rejections on mobile.
// -------------------------------------------------------------------
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: async (req, file) => {
        const isPdf = file.mimetype === 'application/pdf' ||
                      file.originalname.toLowerCase().endsWith('.pdf');
        return {
            folder:          'vault_secure',
            resource_type:   'auto',          // lets Cloudinary handle both PDF and image
            allowed_formats: ['jpg', 'jpeg', 'png', 'heic', 'heif', 'webp', 'pdf'],
            // For images: eager-transform to JPEG so we always have a viewable URL
            // For PDFs:  Cloudinary auto-generates a jpg preview via URL params (see below)
            ...(isPdf ? {} : {
                format: 'jpg',
                transformation: [{ quality: 'auto', fetch_format: 'jpg' }]
            })
        };
    }
});

// FIX 4: Raise multer's file-size ceiling (50 MB) so large mobile PDFs aren't
// rejected before they even reach Cloudinary.
const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB
    fileFilter: (req, file, cb) => {
        const allowed = [
            'image/jpeg', 'image/jpg', 'image/png',
            'image/heic', 'image/heif', 'image/webp',
            'application/pdf',
            'application/octet-stream' // iOS Safari sometimes sends PDFs as this
        ];
        if (allowed.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error(`Unsupported file type: ${file.mimetype}`), false);
        }
    }
});

// --- MONGODB SCHEMA ---
const DocumentSchema = new mongoose.Schema({
    type:  String,
    name:  String,
    date:  String,
    pdf:   String, // encrypted Cloudinary URL (raw/image)
    jpeg:  String, // encrypted JPEG-viewable URL
    size:  Number
});

const PersonSchema = new mongoose.Schema({
    name:      { type: String, required: true, unique: true },
    documents: [DocumentSchema]
});

const Person = mongoose.model('Person', PersonSchema);

// -------------------------------------------------------------------
// FIX 5: Build correct JPEG preview URL for PDFs.
// Instead of naive string-replace (.pdf → .jpg), use Cloudinary's
// URL transformation API to render page 1 of the PDF as a JPEG.
// -------------------------------------------------------------------
function buildJpegUrl(cloudinaryUrl, isPdf) {
    if (!isPdf) return cloudinaryUrl; // already an image URL

    // Cloudinary PDF-to-JPEG: swap resource type path & set format + page
    // Input:  https://res.cloudinary.com/<c>/raw/upload/v.../vault_secure/doc.pdf
    // Output: https://res.cloudinary.com/<c>/image/upload/pg_1,f_jpg,q_auto/v.../vault_secure/doc
    try {
        let url = cloudinaryUrl;

        // 1. Switch resource-type segment from 'raw' to 'image'
        url = url.replace('/raw/upload/', '/image/upload/');

        // 2. Inject transformation string right after /upload/
        url = url.replace('/image/upload/', '/image/upload/pg_1,f_jpg,q_auto/');

        // 3. Strip .pdf extension so Cloudinary serves JPEG
        url = url.replace(/\.pdf$/i, '');

        return url;
    } catch (e) {
        return cloudinaryUrl;
    }
}

// --- DECRYPT & RESHAPE PERSON ---
const decryptPerson = (p) => {
    const personObj = p.toObject ? p.toObject() : p;
    return {
        _id:       personObj._id.toString(),
        name:      personObj.name,
        documents: (personObj.documents || []).map(d => ({
            _id:  d._id.toString(),
            type: d.type,
            name: d.name,
            date: d.date,
            size: d.size,
            pdf:  decrypt(d.pdf),
            jpeg: decrypt(d.jpeg)
        }))
    };
};

// --- API ROUTES ---

router.get('/people', async (req, res) => {
    try {
        const people = await Person.find();
        res.json(people.map(decryptPerson));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.post('/people', async (req, res) => {
    try {
        const person = new Person({ name: req.body.name, documents: [] });
        await person.save();
        res.json(decryptPerson(person));
    } catch (err) {
        res.status(400).json({ error: 'Person already exists or invalid name' });
    }
});

router.delete('/people/:id', async (req, res) => {
    try {
        const person = await Person.findById(req.params.id);
        if (person) {
            for (const doc of person.documents) {
                const realUrl = decrypt(doc.pdf);
                const publicId = getPublicIdFromUrl(realUrl);
                // FIX 6: Use correct resource_type so deletes actually work
                const resType  = getResourceTypeFromUrl(realUrl);
                if (publicId) {
                    await cloudinary.uploader
                        .destroy(publicId, { resource_type: resType })
                        .catch(e => console.warn('Cloudinary delete warn:', e.message));
                }
            }
        }
        await Person.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// FIX 7: Multer error middleware so upload errors (size, type) reach the client
//         instead of crashing the request silently on mobile.
router.post('/documents/:personId',
    (req, res, next) => {
        upload.single('file')(req, res, (err) => {
            if (err) {
                console.error('Multer/Cloudinary upload error:', err);
                if (err.code === 'LIMIT_FILE_SIZE') {
                    return res.status(413).json({ error: 'File too large. Maximum size is 50 MB.' });
                }
                return res.status(400).json({ error: err.message || 'File upload failed' });
            }
            next();
        });
    },
    async (req, res) => {
        try {
            const person = await Person.findById(req.params.personId);
            if (!person) return res.status(404).json({ error: 'Person not found' });

            if (!req.file) return res.status(400).json({ error: 'No file received by server' });

            const uploadedUrl  = req.file.path;   // Cloudinary secure URL
            const fileSize     = req.file.size || 0;
            const originalName = req.file.originalname || '';

            // FIX 5 applied: build a proper JPEG preview URL for PDFs
            const isPdf = originalName.toLowerCase().endsWith('.pdf') ||
                          req.file.mimetype === 'application/pdf';
            const jpegUrl = buildJpegUrl(uploadedUrl, isPdf);

            console.log(`Uploaded [${isPdf ? 'PDF' : 'IMAGE'}]: ${uploadedUrl}`);
            console.log(`JPEG preview URL: ${jpegUrl}`);

            const newDoc = {
                type: req.body.type,
                name: req.body.name,
                date: req.body.date,
                size: fileSize,
                pdf:  encrypt(uploadedUrl),
                jpeg: encrypt(jpegUrl)
            };

            person.documents.push(newDoc);
            await person.save();
            res.json(decryptPerson(person));
        } catch (err) {
            console.error('Document save error:', err);
            res.status(500).json({ error: err.message });
        }
    }
);

router.delete('/documents/:personId/:docId', async (req, res) => {
    try {
        const person = await Person.findById(req.params.personId);
        if (!person) return res.status(404).json({ error: 'Person not found' });

        const doc = person.documents.id(req.params.docId);
        if (doc) {
            const realUrl  = decrypt(doc.pdf);
            const publicId = getPublicIdFromUrl(realUrl);
            // FIX 6: Correct resource_type for delete
            const resType  = getResourceTypeFromUrl(realUrl);
            if (publicId) {
                await cloudinary.uploader
                    .destroy(publicId, { resource_type: resType })
                    .catch(e => console.warn('Cloudinary delete warn:', e.message));
            }
        }

        person.documents.pull({ _id: req.params.docId });
        await person.save();
        res.json(decryptPerson(person));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.use('/api', router);

// Serve Frontend
app.get('/', (req, res) => {
   
   
    res.render('index');
});
app.use(express.static(path.join(process.cwd(), 'public')));

// Port Discovery
function startServer(port) {
    const numericPort = Number(port);
    app.listen(numericPort, () => {
        console.log('-------------------------------------------');
        console.log(`Vault Running: http://localhost:${numericPort}`);
        console.log('-------------------------------------------');
    }).on('error', e => {
        if (e.code === 'EADDRINUSE') {
            startServer(numericPort + 1);
        } else {
            console.error('Server error:', e);
        }
    });
}

const INITIAL_PORT = process.env.PORT || 5000;
mongoose.connect(MONGO_URI).then(() => startServer(INITIAL_PORT));

module.exports = router;