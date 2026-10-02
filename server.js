import express from "express";
import session from "express-session";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.set("trust proxy", 1);

const db = new Database(path.join(__dirname, "darajati.db"));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || "darajati-school-secret-change-this",
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
`);

/*
  حسابات الإدارة:
  A / 1996A1996
  S / 1995S1995

  يتم تحديثهما تلقائياً عند تشغيل الخادم.
  الحساب القديم admin يتم تعطيله حتى لا يبقى دخول قديم.
*/
const ensureTeacher = db.prepare(`
  INSERT INTO teachers(username,password)
  VALUES(?,?)
  ON CONFLICT(username) DO UPDATE SET password=excluded.password
`);

ensureTeacher.run("A", bcrypt.hashSync("1996A1996", 10));
ensureTeacher.run("S", bcrypt.hashSync("1995S1995", 10));
db.prepare("DELETE FROM teachers WHERE username NOT IN ('A','S')").run();

app.use(express.static(path.join(__dirname, "public")));

function auth(req, res, next) {
  if (!req.session || !req.session.teacherId) {
    return res.status(401).json({ error: "غير مصرح" });
  }
  next();
}

function code3() {
  for (let i = 0; i < 1000; i++) {
    const code = String(Math.floor(100 + Math.random() * 900));
    if (!db.prepare("SELECT id FROM students WHERE code=?").get(code)) return code;
  }
  throw new Error("تعذر إنشاء رمز فريد");
}

function average(a, b) {
  if (a == null || b == null || a === "" || b === "") return null;
  return (Number(a) + Number(b)) / 2;
}

function calc(g = {}) {
  const f1 = average(g.m1_t1, g.m2_t1);
  const f2 = average(g.m1_t2, g.m2_t2);

  // السعي السنوي = (سعي الفصل الأول + نصف السنة + سعي الفصل الثاني) ÷ 3
  const annual =
    f1 != null && g.midyear != null && f2 != null
      ? (Number(f1) + Number(g.midyear) + Number(f2)) / 3
      : null;

  return { ...g, f1, f2, annual };
}

app.post("/api/login", (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    const teacher = db.prepare(
      "SELECT * FROM teachers WHERE username=?"
    ).get(username);

    if (!teacher || !bcrypt.compareSync(password, teacher.password)) {
      return res.status(401).json({
        error: "اسم المستخدم أو كلمة المرور غير صحيحة"
      });
    }

    req.session.teacherId = teacher.id;
    req.session.teacherUsername = teacher.username;

    req.session.save(err => {
      if (err) return res.status(500).json({ error: "تعذر حفظ جلسة الدخول" });
      res.json({ ok: true });
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "حدث خطأ في تسجيل الدخول" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: "تعذر تسجيل الخروج" });
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

app.get("/api/me", (req, res) => {
  res.json({
    loggedIn: !!(req.session && req.session.teacherId),
    username: req.session?.teacherUsername || null
  });
});

app.get("/api/students", auth, (req, res) => {
  res.json(db.prepare(
    "SELECT * FROM students ORDER BY class_name,name"
  ).all());
});

app.post("/api/students", auth, (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const className = String(req.body.class_name || "").trim();

    if (!name || !className) {
      return res.status(400).json({ error: "الاسم والصف مطلوبان" });
    }

    const code = code3();
    const r = db.prepare(
      "INSERT INTO students(name,class_name,code) VALUES(?,?,?)"
    ).run(name, className, code);

    db.prepare("INSERT INTO grades(student_id) VALUES(?)")
      .run(r.lastInsertRowid);

    res.json({
      ok: true,
      id: r.lastInsertRowid,
      name,
      class_name: className,
      code
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "تعذر إضافة الطالب" });
  }
});

app.delete("/api/students/:id", auth, (req, res) => {
  db.prepare("DELETE FROM students WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

app.get("/api/grades", auth, (req, res) => {
  const rows = db.prepare(`
    SELECT s.id,s.name,s.class_name,s.code,
           g.m1_t1,g.m2_t1,g.midyear,g.m1_t2,g.m2_t2
    FROM students s
    LEFT JOIN grades g ON g.student_id=s.id
    ORDER BY s.class_name,s.name
  `).all();

  res.json(rows.map(calc));
});

app.put("/api/grades/:id", auth, (req, res) => {
  try {
    const b = req.body || {};

    db.prepare(`
      INSERT INTO grades(student_id,m1_t1,m2_t1,midyear,m1_t2,m2_t2)
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

    const g = db.prepare(
      "SELECT * FROM grades WHERE student_id=?"
    ).get(req.params.id);

    res.json(calc(g));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "تعذر حفظ الدرجات" });
  }
});

app.get("/api/attendance", auth, (req, res) => {
  const date = String(req.query.date || "");
  res.json(db.prepare(`
    SELECT a.*,s.name,s.class_name
    FROM attendance a
    JOIN students s ON s.id=a.student_id
    WHERE a.date=?
    ORDER BY s.class_name,s.name
  `).all(date));
});

app.post("/api/attendance", auth, (req, res) => {
  try {
    const date = String(req.body.date || "");
    const records = Array.isArray(req.body.records) ? req.body.records : [];

    if (!date) return res.status(400).json({ error: "التاريخ مطلوب" });

    const q = db.prepare(`
      INSERT INTO attendance(student_id,date,status)
      VALUES(?,?,?)
      ON CONFLICT(student_id,date)
      DO UPDATE SET status=excluded.status
    `);

    const tx = db.transaction(items => {
      for (const item of items) {
        q.run(item.student_id, date, item.status);
      }
    });

    tx(records);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "تعذر حفظ الحضور" });
  }
});

app.get("/api/exams", auth, (req, res) => {
  res.json(db.prepare(
    "SELECT * FROM exams ORDER BY date,time"
  ).all());
});

app.post("/api/exams", auth, (req, res) => {
  try {
    const b = req.body || {};
    if (!b.class_name || !b.type || !b.date) {
      return res.status(400).json({ error: "الصف والنوع والتاريخ مطلوبة" });
    }

    const r = db.prepare(`
      INSERT INTO exams(class_name,type,date,time,note)
      VALUES(?,?,?,?,?)
    `).run(
      b.class_name, b.type, b.date, b.time || "", b.note || ""
    );

    res.json(db.prepare(
      "SELECT * FROM exams WHERE id=?"
    ).get(r.lastInsertRowid));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "تعذر إضافة الامتحان" });
  }
});

app.delete("/api/exams/:id", auth, (req, res) => {
  db.prepare("DELETE FROM exams WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

app.get("/api/notices", auth, (req, res) => {
  res.json(db.prepare(
    "SELECT * FROM notices ORDER BY id DESC"
  ).all());
});

app.post("/api/notices", auth, (req, res) => {
  try {
    const b = req.body || {};
    if (!b.class_name || !b.title || !b.body) {
      return res.status(400).json({ error: "الصف والعنوان والنص مطلوبة" });
    }

    const r = db.prepare(`
      INSERT INTO notices(class_name,type,title,body,created_at)
      VALUES(?,?,?,?,datetime('now','localtime'))
    `).run(
      b.class_name,
      b.type || "تبليغ عام",
      b.title,
      b.body
    );

    res.json(db.prepare(
      "SELECT * FROM notices WHERE id=?"
    ).get(r.lastInsertRowid));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "تعذر إضافة التبليغ" });
  }
});

app.delete("/api/notices/:id", auth, (req, res) => {
  db.prepare("DELETE FROM notices WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

app.get("/api/portal/:code", (req, res) => {
  try {
    const code = String(req.params.code || "").trim();
    const student = db.prepare(`
      SELECT id,name,class_name,code
      FROM students
      WHERE code=?
    `).get(code);

    if (!student) {
      return res.status(404).json({ error: "الرمز السري غير صحيح" });
    }

    const grades = db.prepare(
      "SELECT * FROM grades WHERE student_id=?"
    ).get(student.id) || {};

    const exams = db.prepare(`
      SELECT * FROM exams
      WHERE class_name=?
      ORDER BY date,time
    `).all(student.class_name);

    const notices = db.prepare(`
      SELECT * FROM notices
      WHERE class_name=? OR class_name='جميع الصفوف'
      ORDER BY id DESC
    `).all(student.class_name);

    const attendance = db.prepare(`
      SELECT date,status
      FROM attendance
      WHERE student_id=?
      ORDER BY date DESC
    `).all(student.id);

    res.json({
      student,
      grades: calc(grades),
      exams,
      notices,
      attendance
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "تعذر عرض بيانات الطالب" });
  }
});

app.use((req,res) => {
  res.sendFile(path.join(__dirname,"public","index.html"));
});

const port = process.env.PORT || 3000;
app.listen(port,"0.0.0.0",() => {
  console.log(`Darajati running on ${port}`);
});
