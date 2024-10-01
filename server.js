const express = require('express')
const pool = require("./database")
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const cors = require('cors')
const multer = require('multer')
const path = require('path');

require('dotenv').config()

const app = express()
app.use(cors())
app.use(express.json())

const port = 4000

app.get('/', (req, res) => res.send('Hello World!'))

app.get('/test', (req, res) => res.send('Test url!'))

// ตรวจสอบ user token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // รับ token จาก header
    if (!token) return res.sendStatus(401); // ถ้าไม่มี token ส่ง status 401
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
      if (err) return res.sendStatus(403); // ถ้า token ไม่ถูกต้อง ส่ง status 403
      req.user = user; // เก็บข้อมูล user ไว้ใน req
      next(); // ดำเนินการต่อไป
    });
  };

// ดึงข้อมูลผู้ใช้งานที่เข้าเข้าระบบ Account
app.get('/account' , authenticateToken, async (req, res) => {
    try {
        const userid = req.user.id;
        const [results] = await pool.query("SELECT email, name, picture  FROM users WHERE id =?", [userid])
        if(results.length === 0) {
            return res.status(404).json({error: "ไม่พบผู้ใช้"})
        }
        res.json(results)
    }catch (err) {
        console.log(err)
        res.status(500).json({ error: "ผิดพลาด"})
    }
})

app.post('/register', async (req, res) => {
    const { email, password, name } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const [result] = await pool.query('INSERT INTO users (email, password, name) VALUES (?, ?, ?)', [email, hashedPassword, name]);
        res.status(201).send('Uesr registerd');
    } catch (error) {
        res.status(500).send('Error register');
    };
});

app.post('/addnew', async (req, res) => {
    const { fname, lname } = req.body;
    try {
        const [result] = await pool.query('INSERT INTO employees (fname, lname) VALUES (?, ?)', [fname, lname]);
        res.status(201).send('เพิ่มข้อมูลสำเร็จ');
    } catch (error) {
        res.status(500).send('Error');
    };
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const [results] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = results[0];
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    if (await bcrypt.compare(password, user.password)) {
        const accessToken = jwt.sign({ id: user.id, email: user.email },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '20h' }
        );
        return res.json({ token: accessToken });
    } else {
        return res.status(401).json({ message: 'Password incorrect' });
    }
});
// กำหนดโฟลเดอร์สำหรับเก็บรูป
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function(req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname))
    }
})



const upload = multer({ storage: storage });
// เปิดให้เข้าถึงไฟล์จากโฟลเดอร์ 'uploads'
app.use('/uploads', express.static('uploads'));

// แก้ไขข้อมูลบัญชีผู้ใช้งาน
app.put('/update-account', authenticateToken , upload.single('picture') , async (req, res) => {
    const { name, email } = req.body;
    const picturePath = req.file ? `uploads/${req.file.filename}` : null;
    try{
        const userid = req.user.id;
        let query = 'UPDATE users SET name=?, email=?'
        let params = [name , email]
        if(picturePath) {
            query += ', picture =? '
            params.push(picturePath)
        }
        query += 'WHERE id =? '
        params.push(userid)
        const [results] = await pool.query(query, params);
        if(results.affectedRows === 0) {
            return res.status(400).json({ error : "ไมพบผู้ใช้"});
        }
        res.json({message: "แก้ไขข้อมูลเรียบร้อย"});
    } catch (err) {
        console.log("Error", err);
        res.status(500).json( {error : "ผิดพลาด"});
    }
})

app.listen(port, () => console.log(`Example app listening on port ${port}!`))