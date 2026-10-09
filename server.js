import express from "express";
import session from "express-session";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import multer from "multer";
import fs from "fs";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const db = new Database(path.join(__dirname, "darajati.db"));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-secret-in-production",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

db.exec(`
CREATE TABLE IF NOT EXISTS teachers(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS students(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  class_name TEXT NOT NULL,
  code TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS grades(
  student_id INTEGER PRIMARY KEY,
  m1_t1 REAL,
  m2_t1 REAL,
  midyear REAL,
  m1_t2 REAL,
  m2_t2 REAL,
  FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attendance(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER,
  date TEXT,
  status TEXT,
  UNIQUE(student_id,date),
  FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS exams(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  class_name TEXT,
  type TEXT,
  date TEXT,
  time TEXT,
  note TEXT
);

CREATE TABLE IF NOT EXISTS notices(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  class_name TEXT,
  type TEXT,
  title TEXT,
  body TEXT,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS handouts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  class_name TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  file_name TEXT NOT NULL,
  original_name TEXT NOT NULL,
  created_at TEXT NOT NULL
);
`);

// Ensure the two requested teacher accounts exist with the specified credentials.
// This only updates the teacher login records; it does not touch student grades or attendance.
const saveTeacher = db.prepare(`
  INSERT INTO teachers(username,password) VALUES(?,?)
  ON CONFLICT(username) DO UPDATE SET password=excluded.password
`);
saveTeacher.run("A", bcrypt.hashSync("1996A1996", 10));
saveTeacher.run("S", bcrypt.hashSync("1995S1995", 10));

const uploadsDir = path.join(__dirname, "public", "handouts");
fs.mkdirSync(uploadsDir, { recursive: true });

const pdfUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadsDir),
    filename: (_req, file, cb) => {
      const safeExt = path.extname(file.originalname || "").toLowerCase();
      cb(null, `${Date.now()}-${crypto.randomUUID()}${safeExt}`);
    }
  }),
  limits: { fileSize: 30 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    if (ext !== ".pdf" || (file.mimetype !== "application/pdf" && file.mimetype !== "application/octet-stream")) {
      return cb(new Error("يسمح برفع ملفات PDF فقط"));
    }
    cb(null, true);
  }
});

app.use(express.static(path.join(__dirname, "public")));

function auth(req, res, next) {
  if (!req.session.teacherId) {
    return res.status(401).json({ error: "غير مصرح" });
  }
  next();
}

function code3() {
  for (let i = 0; i < 1000; i++) {
    const c = String(Math.floor(100 + Math.random() * 900));
    if (!db.prepare("SELECT id FROM students WHERE code=?").get(c)) {
      return c;
    }
  }
  throw new Error("تعذر إنشاء رمز فريد");
}

/*
  حساب الدرجات:
  سعي الفصل الأول = (الشهر الأول ف1 + الشهر الثاني ف1) ÷ 2
  سعي الفصل الثاني = (الشهر الأول ف2 + الشهر الثاني ف2) ÷ 2

  السعي السنوي =
  (سعي الفصل الأول + نصف السنة + سعي الفصل الثاني) ÷ 3
*/
function calc(g = {}) {
  const avg = (a, b) =>
    a == null || b == null ? null : (Number(a) + Number(b)) / 2;

  const f1 = avg(g.m1_t1, g.m2_t1);
  const f2 = avg(g.m1_t2, g.m2_t2);

  const annual =
    f1 == null || g.midyear == null || f2 == null
      ? null
      : (Number(f1) + Number(g.midyear) + Number(f2)) / 3;

  return {
    ...g,
    f1,
    f2,
    annual
  };
}

app.post("/api/login", (req, res) => {
  const t = db
    .prepare("SELECT * FROM teachers WHERE username=?")
    .get((req.body.username || "").trim());

  if (!t || !bcrypt.compareSync(req.body.password || "", t.password)) {
    return res.status(401).json({
      error: "اسم المستخدم أو كلمة المرور غير صحيحة"
    });
  }

  req.session.teacherId = t.id;
  res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", (req, res) => {
  res.json({ loggedIn: !!req.session.teacherId });
});

app.get("/api/students", auth, (req, res) => {
  res.json(
    db
      .prepare("SELECT * FROM students ORDER BY class_name,name")
      .all()
  );
});

app.post("/api/students", auth, (req, res) => {
  const name = (req.body.name || "").trim();
  const cls = (req.body.class_name || "").trim();

  if (!name || !cls) {
    return res.status(400).json({
      error: "الاسم والصف مطلوبان"
    });
  }

  const code = code3();

  const r = db
    .prepare("INSERT INTO students(name,class_name,code) VALUES(?,?,?)")
    .run(name, cls, code);

  db.prepare("INSERT INTO grades(student_id) VALUES(?)")
    .run(r.lastInsertRowid);

  res.json({
    id: r.lastInsertRowid,
    name,
    class_name: cls,
    code
  });
});

app.delete("/api/students/:id", auth, (req, res) => {
  db.prepare("DELETE FROM students WHERE id=?")
    .run(req.params.id);

  res.json({ ok: true });
});

app.get("/api/grades", auth, (req, res) => {
  const rows = db.prepare(`
    SELECT
      s.id,
      s.name,
      s.class_name,
      s.code,
      g.m1_t1,
      g.m2_t1,
      g.midyear,
      g.m1_t2,
      g.m2_t2
    FROM students s
    LEFT JOIN grades g ON g.student_id=s.id
    ORDER BY s.class_name,s.name
  `).all();

  res.json(rows.map(r => calc(r)));
});

app.put("/api/grades/:id", auth, (req, res) => {
  const b = req.body;

  db.prepare(`
    INSERT INTO grades(
      student_id,
      m1_t1,
      m2_t1,
      midyear,
      m1_t2,
      m2_t2
    )
    VALUES(?,?,?,?,?,?)
    ON CONFLICT(student_id) DO UPDATE SET
      m1_t1=excluded.m1_t1,
      m2_t1=excluded.m2_t1,
      midyear=excluded.midyear,
      m1_t2=excluded.m1_t2,
      m2_t2=excluded.m2_t2
  `).run(
    req.params.id,
    b.m1_t1 ?? null,
    b.m2_t1 ?? null,
    b.midyear ?? null,
    b.m1_t2 ?? null,
    b.m2_t2 ?? null
  );

  res.json(
    calc(
      db.prepare("SELECT * FROM grades WHERE student_id=?")
        .get(req.params.id)
    )
  );
});

app.get("/api/attendance", auth, (req, res) => {
  res.json(
    db.prepare(`
      SELECT a.*,s.name,s.class_name
      FROM attendance a
      JOIN students s ON s.id=a.student_id
      WHERE a.date=?
      ORDER BY s.class_name,s.name
    `).all(req.query.date || "")
  );
});

app.post("/api/attendance", auth, (req, res) => {
  const { date, records } = req.body;

  const q = db.prepare(`
    INSERT INTO attendance(student_id,date,status)
    VALUES(?,?,?)
    ON CONFLICT(student_id,date)
    DO UPDATE SET status=excluded.status
  `);

  const tx = db.transaction(rs =>
    (rs || []).forEach(x =>
      q.run(x.student_id, date, x.status)
    )
  );

  tx(records || []);
  res.json({ ok: true });
});

app.get("/api/exams", auth, (req, res) => {
  res.json(
    db.prepare("SELECT * FROM exams ORDER BY date,time").all()
  );
});

app.post("/api/exams", auth, (req, res) => {
  const b = req.body;

  if (!b.class_name || !b.type || !b.date) {
    return res.status(400).json({
      error: "الصف والنوع والتاريخ مطلوبة"
    });
  }

  const r = db.prepare(`
    INSERT INTO exams(class_name,type,date,time,note)
    VALUES(?,?,?,?,?)
  `).run(
    b.class_name,
    b.type,
    b.date,
    b.time || "",
    b.note || ""
  );

  res.json(
    db.prepare("SELECT * FROM exams WHERE id=?")
      .get(r.lastInsertRowid)
  );
});

app.delete("/api/exams/:id", auth, (req, res) => {
  db.prepare("DELETE FROM exams WHERE id=?")
    .run(req.params.id);

  res.json({ ok: true });
});

app.get("/api/notices", auth, (req, res) => {
  res.json(
    db.prepare("SELECT * FROM notices ORDER BY id DESC").all()
  );
});

app.post("/api/notices", auth, (req, res) => {
  const b = req.body;

  if (!b.class_name || !b.title || !b.body) {
    return res.status(400).json({
      error: "الصف والعنوان والنص مطلوبة"
    });
  }

  const r = db.prepare(`
    INSERT INTO notices(
      class_name,
      type,
      title,
      body,
      created_at
    )
    VALUES(?,?,?,?,datetime('now','localtime'))
  `).run(
    b.class_name,
    b.type || "تبليغ عام",
    b.title,
    b.body
  );

  res.json(
    db.prepare("SELECT * FROM notices WHERE id=?")
      .get(r.lastInsertRowid)
  );
});

app.delete("/api/notices/:id", auth, (req, res) => {
  db.prepare("DELETE FROM notices WHERE id=?")
    .run(req.params.id);

  res.json({ ok: true });
});


// إحصائيات الصفوف — متاحة للمدرس فقط
app.get("/api/statistics", auth, (req, res) => {
  const studentRows = db.prepare(`
    SELECT s.id,s.name,s.class_name,
      g.m1_t1,g.m2_t1,g.midyear,g.m1_t2,g.m2_t2
    FROM students s LEFT JOIN grades g ON g.student_id=s.id
    ORDER BY s.class_name,s.name
  `).all().map(r => ({...r, ...calc(r)}));

  const attendance = db.prepare(`
    SELECT s.class_name,a.status,COUNT(*) AS count
    FROM attendance a JOIN students s ON s.id=a.student_id
    GROUP BY s.class_name,a.status
  `).all();

  const byClass = {};
  for (const cls of ["الثالث المتوسط","الرابع العلمي","الخامس العلمي","السادس العلمي"]) {
    const rows = studentRows.filter(s => s.class_name === cls);
    const complete = rows.filter(s => s.annual != null);
    const passing = complete.filter(s => s.annual > 50).length;
    const failing = complete.filter(s => s.annual < 50).length;
    const equal = complete.filter(s => s.annual === 50).length;
    const average = complete.length ? complete.reduce((sum,s)=>sum+Number(s.annual),0)/complete.length : null;
    byClass[cls] = {
      students: rows.length,
      withAnnual: complete.length,
      passing, failing, equal, average,
      attendance: attendance.filter(a=>a.class_name===cls)
    };
  }
  res.json({ byClass, totalStudents: studentRows.length });
});

// إدارة الملازم: رفع PDF موجه لصف محدد أو لجميع الصفوف
app.get("/api/handouts", auth, (_req, res) => {
  res.json(db.prepare("SELECT * FROM handouts ORDER BY id DESC").all());
});

app.post("/api/handouts", auth, (req, res, next) => {
  pdfUpload.single("file")(req, res, err => {
    if (err) {
      const message = err.code === "LIMIT_FILE_SIZE"
        ? "حجم الملف أكبر من 30 ميغابايت"
        : (err.message || "تعذر رفع الملف");
      return res.status(400).json({ error: message });
    }
    try {
      const title = (req.body.title || "").trim();
      const className = (req.body.class_name || "").trim();
      const description = (req.body.description || "").trim();
      if (!title || !className || !req.file) {
        if (req.file) fs.unlink(req.file.path, () => {});
        return res.status(400).json({ error: "العنوان والصف وملف PDF مطلوبة" });
      }
      const result = db.prepare(`
        INSERT INTO handouts(class_name,title,description,file_name,original_name,created_at)
        VALUES(?,?,?,?,?,datetime('now','localtime'))
      `).run(className, title, description, req.file.filename, req.file.originalname);
      res.json(db.prepare("SELECT * FROM handouts WHERE id=?").get(result.lastInsertRowid));
    } catch (e) {
      if (req.file) fs.unlink(req.file.path, () => {});
      next(e);
    }
  });
});

app.delete("/api/handouts/:id", auth, (req, res) => {
  const item = db.prepare("SELECT * FROM handouts WHERE id=?").get(req.params.id);
  if (!item) return res.status(404).json({ error: "الملزمة غير موجودة" });
  db.prepare("DELETE FROM handouts WHERE id=?").run(req.params.id);
  fs.unlink(path.join(uploadsDir, item.file_name), () => {});
  res.json({ ok: true });
});

app.get("/api/portal/:code", (req, res) => {
  const s = db.prepare(`
    SELECT id,name,class_name,code
    FROM students
    WHERE code=?
  `).get(req.params.code);

  if (!s) {
    return res.status(404).json({
      error: "الرمز السري غير صحيح"
    });
  }

  const g = db.prepare(`
    SELECT *
    FROM grades
    WHERE student_id=?
  `).get(s.id) || {};

  const exams = db.prepare(`
    SELECT *
    FROM exams
    WHERE class_name=?
    ORDER BY date,time
  `).all(s.class_name);

  const notices = db.prepare(`
    SELECT *
    FROM notices
    WHERE class_name=? OR class_name='جميع الصفوف'
    ORDER BY id DESC
  `).all(s.class_name);

  const attendance = db.prepare(`
    SELECT date,status
    FROM attendance
    WHERE student_id=?
    ORDER BY date DESC
  `).all(s.id);

  const handouts = db.prepare(`
    SELECT id,class_name,title,description,file_name,original_name,created_at
    FROM handouts
    WHERE class_name=? OR class_name='جميع الصفوف'
    ORDER BY id DESC
  `).all(s.class_name);

  res.json({
    student: s,
    grades: calc(g),
    exams,
    notices,
    attendance,
    handouts
  });
});

app.use((req, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"))
);

const port = process.env.PORT || 3000;

app.listen(port, "0.0.0.0", () =>
  console.log(`Darajati running on ${port}`)
);
