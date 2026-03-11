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

// --- CLOUDINARY UTILS ---
function getPublicIdFromUrl(url) {
    if (!url) return null;
    try {
        const match = url.match(/\/upload\/(?:v\d+\/)?(.+)$/);
        if (!match) return null;
        const withExt = match[1]; 
        return withExt.replace(/\.[^/.]+$/, ''); 
    } catch (e) {
        return null;
    }
}

function getResourceTypeFromUrl(url) {
    if (!url) return 'image';
    if (url.includes('/raw/upload/'))   return 'raw';
    if (url.includes('/video/upload/')) return 'video';
    return 'image';
}

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: async (req, file) => {
        const isPdf = file.mimetype === 'application/pdf' ||
                      file.originalname.toLowerCase().endsWith('.pdf');
        return {
            folder:          'vault_secure',
            resource_type:   'auto',
            allowed_formats: ['jpg', 'jpeg', 'png', 'heic', 'heif', 'webp', 'pdf'],
            ...(isPdf ? {} : {
                format: 'jpg',
                transformation: [{ quality: 'auto', fetch_format: 'jpg' }]
            })
        };
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB
    fileFilter: (req, file, cb) => {
        const allowed = [
            'image/jpeg', 'image/jpg', 'image/png',
            'image/heic', 'image/heif', 'image/webp',
            'application/pdf',
            'application/octet-stream'
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
    pdf:   String,
    jpeg:  String,
    size:  Number
});

const PersonSchema = new mongoose.Schema({
    name:      { type: String, required: true, unique: true },
    documents: [DocumentSchema]
});

const Person = mongoose.model('Person', PersonSchema);

function buildJpegUrl(cloudinaryUrl, isPdf) {
    if (!isPdf) return cloudinaryUrl;
    try {
        let url = cloudinaryUrl;
        url = url.replace('/raw/upload/', '/image/upload/');
        url = url.replace('/image/upload/', '/image/upload/pg_1,f_jpg,q_auto/');
        url = url.replace(/\.pdf$/i, '');
        return url;
    } catch (e) {
        return cloudinaryUrl;
    }
}

const decryptPerson = (p) => {
    const personObj = p.toObject ? p.toObject() : p;
    return {
        _id:       personObj._id.toString(),
        name:       personObj.name,
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

router.post('/documents/:personId',
    (req, res, next) => {
        upload.single('file')(req, res, (err) => {
            if (err) {
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

            const uploadedUrl  = req.file.path;
            const fileSize     = req.file.size || 0;
            const originalName = req.file.originalname || '';
            const isPdf = originalName.toLowerCase().endsWith('.pdf') ||
                          req.file.mimetype === 'application/pdf';
            const jpegUrl = buildJpegUrl(uploadedUrl, isPdf);

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
app.get('/', (req, res) => res.render('index'));
app.use(express.static(path.join(process.cwd(), 'public')));

// --- SERVER STARTUP ---
// On Render, the port is provided via process.env.PORT. 
// We use 3000 only as a local fallback.
const PORT = process.env.PORT || 3000;

mongoose.connect(MONGO_URI)
    .then(() => {
        console.log('Connected to MongoDB.');
        app.listen(PORT, '0.0.0.0', () => {
            console.log('-------------------------------------------');
            console.log(`Vault Server running on port: ${PORT}`);
            console.log('-------------------------------------------');
        });
    })
    .catch(err => {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    });

module.exports = app;