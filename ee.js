const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const dbConnection = require('./dbConnection');
const { body, validationResult } = require('express-validator');

// Middleware สำหรับตรวจสอบการล็อกอิน
const ifNotLoggedIn = (req, res, next) => {
    if (!req.session.isLoggedIn) {
        return res.render('login'); // ถ้ายังไม่ล็อกอิน ให้ไปที่หน้า login
    }
    next();
};

const ifLoggedin = (req, res, next) => {
    if (req.session.isLoggedIn) {
        return res.redirect('/home'); // ถ้าล็อกอินแล้ว ให้ไปหน้า home
    }
    next();
};

// เส้นทางสำหรับการล็อกอิน Flutter (ใช้ POST /api/login)
router.post('/api/login', async (req, res) => {
    const { id_number, password } = req.body;

    // ตรวจสอบว่ามีการส่ง id_number และ password มาหรือไม่
    if (!id_number || !password) {
        return res.status(400).json({ error: 'ID number and password are required' });
    }

    try {
        const [rows] = await dbConnection.execute("SELECT * FROM users WHERE id_number = ?", [id_number]);
        if (rows.length > 0) {
            const user = rows[0];
            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                return res.status(200).json({ message: 'Login successful', user: { id: user.id_number, role: user.role } });
            } else {
                return res.status(401).json({ error: 'Invalid password' });
            }
        } else {
            return res.status(401).json({ error: 'Invalid ID number' });
        }
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// เส้นทางล็อกอินสำหรับเว็บ (ใช้ POST /login)
router.post('/login', async (req, res) => {
    const { id_number, password } = req.body;

    // ตรวจสอบว่ามีการส่ง id_number และ password มาหรือไม่
    if (!id_number || !password) {
        return res.status(400).json({ error: 'ID number and password are required' });
    }

    try {
        const [rows] = await dbConnection.execute("SELECT * FROM users WHERE id_number = ?", [id_number]);
        if (rows.length > 0) {
            const user = rows[0];
            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                req.session.isLoggedIn = true;
                req.session.userID = user.id_number;
                return res.status(200).json({ message: 'Login successful', user });
            } else {
                return res.status(401).json({ error: 'Invalid password' });
            }
        } else {
            return res.status(401).json({ error: 'Invalid ID number' });
        }
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: 'An error occurred during login' });
    }
});

// HOME PAGE สำหรับเว็บ
router.get('/home', ifNotLoggedIn, async (req, res) => {
    const teacherId = req.session.userID;
    if (!teacherId) {
        return res.redirect('/login');
    }
    try {
        const [[user]] = await dbConnection.execute('SELECT role FROM users WHERE id_number = ?', [teacherId]);
        if (!user || user.role !== 'teacher') {
            return res.status(403).send('Forbidden: Only teachers can access this page');
        }

        // ดึงข้อมูลรายวิชาที่อาจารย์สอน
        const [rows] = await dbConnection.execute(`
            SELECT c.course_code, c.course_name, c.section, c.year
            FROM courses c
            JOIN course_teachers ct ON c.course_code = ct.course_code AND c.section = ct.section
            WHERE ct.teacher_id = ?
        `, [teacherId]);

        const courses = rows.map(row => ({
            course_code: row.course_code,
            name: `${row.course_code} - ${row.course_name}`,
            year: row.year,
            section: row.section
        }));

        res.render('home', { subjects: courses });
    } catch (err) {
        console.error(err);
        res.status(500).send('An error occurred');
    }
});

// เส้นทาง Logout
router.get('/logout', (req, res) => {
    req.session = null; // ล้าง session
    res.redirect('/'); // กลับไปที่หน้า login
});

// Classroom
router.get('/Classroom', ifNotLoggedIn, async (req, res) => {
    const teacherId = req.session.userID;
    if (!teacherId) {
        return res.redirect('/login');
    }
    try {
        const [rows] = await dbConnection.execute(`
            SELECT c.course_code, c.course_name, c.section, c.year
            FROM courses c
            JOIN course_teachers ct ON c.course_code = ct.course_code AND c.section = ct.section
            WHERE ct.teacher_id = ?
        `, [teacherId]);

        const courses = rows.map(row => ({
            course_code: row.course_code,
            name: `${row.course_code} - ${row.course_name}`,
            year: row.year,
            section: row.section
        }));

        res.render('Classroom', { subjects: courses });
    } catch (err) {
        console.error(err);
        res.status(500).send('An error occurred');
    }
});

module.exports = router;
