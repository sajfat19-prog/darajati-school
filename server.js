import express from "express";
import session from "express-session";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();

/* مهم عند تشغيل الموقع على Railway */
app.set("trust proxy", 1);

/* قاعدة البيانات */
const db = new Database(path.join(__dirname, "darajati.db"));

/* قراءة البيانات */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* جلسة الأستاذ */
app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      "darajati-school-secret-change-this",

    resave: false,
    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 8 * 60 * 60 * 1000
    }
  })
);

/* =========================
   إنشاء جداول قاعدة البيانات
========================= */

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
  FOREIGN KEY(student_id)
    REFERENCES students(id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attendance(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER,
  date TEXT,
  status TEXT,
  UNIQUE(student_id,date),
  FOREIGN KEY(student_id)
    REFERENCES students(id)
    ON DELETE CASCADE
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

/* =========================
   إنشاء حساب الأستاذ تلقائياً
========================= */

const teacher = db
  .prepare("SELECT id FROM teachers LIMIT 1")
  .get();

if (!teacher) {
  const hashedPassword = bcrypt.hashSync("123456", 10);

  db.prepare(
    "INSERT INTO teachers(username,password) VALUES(?,?)"
  ).run("admin", hashedPassword);
}

/* =========================
   الملفات العامة
========================= */

app.use(express.static(path.join(__dirname, "public")));

/* =========================
   التحقق من تسجيل الأستاذ
========================= */

function auth(req, res, next) {
  if (!req.session || !req.session.teacherId) {
    return res.status(401).json({
      error: "غير مصرح"
    });
  }

  next();
}

/* =========================
   إنشاء رقم سري من 3 أرقام
========================= */

function code3() {
  for (let i = 0; i < 1000; i++) {
    const code = String(
      Math.floor(100 + Math.random() * 900)
    );

    const exists = db
      .prepare("SELECT id FROM students WHERE code=?")
      .get(code);

    if (!exists) {
      return code;
    }
  }

  throw new Error("تعذر إنشاء رمز فريد");
}

/* =========================
   حساب الدرجات
========================= */

function calc(g = {}) {
  const avg = (a, b) => {
    if (a == null || b == null || a === "" || b === "") {
      return null;
    }

    return (Number(a) + Number(b)) / 2;
  };

  const f1 = avg(g.m1_t1, g.m2_t1);

  const f2 = avg(g.m1_t2, g.m2_t2);

  const annual = avg(f1, f2);

  return {
    ...g,
    f1,
    f2,
    annual
  };
}

/* =========================
   تسجيل دخول الأستاذ
========================= */

app.post("/api/login", (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    const teacher = db
      .prepare("SELECT * FROM teachers WHERE username=?")
      .get(username);

    if (
      !teacher ||
      !bcrypt.compareSync(password, teacher.password)
    ) {
      return res.status(401).json({
        error: "اسم المستخدم أو كلمة المرور غير صحيحة"
      });
    }

    /*
      حفظ رقم الأستاذ داخل الجلسة
    */
    req.session.teacherId = teacher.id;

    /*
      مهم جداً:
      ننتظر حتى يتم حفظ الجلسة قبل إرسال الرد.
      هذا يمنع ظهور "غير مصرح" عند الضغط مباشرة
      على إضافة طالب بعد تسجيل الدخول.
    */
    req.session.save((err) => {
      if (err) {
        console.error("Session save error:", err);

        return res.status(500).json({
          error: "تعذر حفظ جلسة تسجيل الدخول"
        });
      }

      res.json({
        ok: true,
        message: "تم تسجيل الدخول بنجاح"
      });
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "حدث خطأ في تسجيل الدخول"
    });
  }
});

/* =========================
   تسجيل خروج الأستاذ
========================= */

app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        error: "تعذر تسجيل الخروج"
      });
    }

    res.clearCookie("connect.sid");

    res.json({
      ok: true
    });
  });
});

/* =========================
   معرفة حالة تسجيل الدخول
========================= */

app.get("/api/me", (req, res) => {
  res.json({
    loggedIn: !!(
      req.session &&
      req.session.teacherId
    )
  });
});

/* ==================================================
   الطلاب
================================================== */

/* عرض جميع الطلاب */

app.get("/api/students", auth, (req, res) => {
  const students = db
    .prepare(
      "SELECT * FROM students ORDER BY class_name,name"
    )
    .all();

  res.json(students);
});

/* إضافة طالب */

app.post("/api/students", auth, (req, res) => {
  try {
    const name = String(
      req.body.name || ""
    ).trim();

    const className = String(
      req.body.class_name || ""
    ).trim();

    if (!name || !className) {
      return res.status(400).json({
        error: "الاسم والصف مطلوبان"
      });
    }

    /* إنشاء الرقم السري */
    const code = code3();

    /* إضافة الطالب */
    const result = db
      .prepare(
        `INSERT INTO students
        (name,class_name,code)
        VALUES(?,?,?)`
      )
      .run(
        name,
        className,
        code
      );

    /* إنشاء سجل درجات فارغ */
    db.prepare(
      "INSERT INTO grades(student_id) VALUES(?)"
    ).run(result.lastInsertRowid);

    res.json({
      ok: true,
      id: result.lastInsertRowid,
      name,
      class_name: className,
      code
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "تعذر إضافة الطالب"
    });
  }
});

/* حذف طالب */

app.delete(
  "/api/students/:id",
  auth
