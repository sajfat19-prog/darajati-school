import express from "express";
import session from "express-session";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const db = new Database(path.join(__dirname, "darajati.db"));
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-secret-in-production",
  resave:false, saveUninitialized:false,
  cookie:{httpOnly:true, sameSite:"lax", secure:process.env.NODE_ENV === "production", maxAge:8*60*60*1000}
}));

db.exec(`
CREATE TABLE IF NOT EXISTS teachers(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, class_name TEXT NOT NULL, code TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS grades(
 student_id INTEGER PRIMARY KEY,
 m1_t1 REAL, m2_t1 REAL, midyear REAL, m1_t2 REAL, m2_t2 REAL,
 FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS attendance(
 id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER, date TEXT, status TEXT,
 UNIQUE(student_id,date), FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS exams(
 id INTEGER PRIMARY KEY AUTOINCREMENT, class_name TEXT, type TEXT, date TEXT, time TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS notices(
 id INTEGER PRIMARY KEY AUTOINCREMENT, class_name TEXT, type TEXT, title TEXT, body TEXT, created_at TEXT);
`);

if(!db.prepare("SELECT id FROM teachers LIMIT 1").get()){
  db.prepare("INSERT INTO teachers(username,password) VALUES(?,?)")
    .run("admin", bcrypt.hashSync("123456",10));
}

app.use(express.static(path.join(__dirname,"public")));

function auth(req,res,next){ if(!req.session.teacherId) return res.status(401).json({error:"غير مصرح"}); next(); }
function code3(){
  for(let i=0;i<1000;i++){
    const c=String(Math.floor(100+Math.random()*900));
    if(!db.prepare("SELECT id FROM students WHERE code=?").get(c)) return c;
  }
  throw new Error("تعذر إنشاء رمز فريد");
}
function calc(g){
  const avg=(a,b)=>a==null||b==null?null:(Number(a)+Number(b))/2;
  const f1=avg(g.m1_t1,g.m2_t1), f2=avg(g.m1_t2,g.m2_t2), annual=avg(f1,f2);
  return {...g, f1,f2,annual};
}

app.post("/api/login", (req,res)=>{
  const t=db.prepare("SELECT * FROM teachers WHERE username=?").get(req.body.username);
  if(!t || !bcrypt.compareSync(req.body.password||"",t.password)) return res.status(401).json({error:"اسم المستخدم أو كلمة المرور غير صحيحة"});
  req.session.teacherId=t.id; res.json({ok:true});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json({loggedIn:!!req.session.teacherId}));

app.get("/api/students",auth,(req,res)=>res.json(db.prepare("SELECT * FROM students ORDER BY class_name,name").all()));
app.post("/api/students",auth,(req,res)=>{
  const name=(req.body.name||"").trim(), cls=(req.body.class_name||"").trim();
  if(!name||!cls) return res.status(400).json({error:"الاسم والصف مطلوبان"});
  const code=code3();
  const r=db.prepare("INSERT INTO students(name,class_name,code) VALUES(?,?,?)").run(name,cls,code);
  db.prepare("INSERT INTO grades(student_id) VALUES(?)").run(r.lastInsertRowid);
  res.json({id:r.lastInsertRowid,name,class_name:cls,code});
});
app.delete("/api/students/:id",auth,(req,res)=>{db.prepare("DELETE FROM students WHERE id=?").run(req.params.id);res.json({ok:true})});

app.get("/api/grades",auth,(req,res)=>{
  const rows=db.prepare(`SELECT s.id,s.name,s.class_name,s.code,g.m1_t1,g.m2_t1,g.midyear,g.m1_t2,g.m2_t2
    FROM students s LEFT JOIN grades g ON g.student_id=s.id ORDER BY s.class_name,s.name`).all();
  res.json(rows.map(r=>calc(r)));
});
app.put("/api/grades/:id",auth,(req,res)=>{
  const b=req.body;
  db.prepare(`INSERT INTO grades(student_id,m1_t1,m2_t1,midyear,m1_t2,m2_t2) VALUES(?,?,?,?,?,?)
    ON CONFLICT(student_id) DO UPDATE SET m1_t1=excluded.m1_t1,m2_t1=excluded.m2_t1,midyear=excluded.midyear,m1_t2=excluded.m1_t2,m2_t2=excluded.m2_t2`)
    .run(req.params.id,b.m1_t1??null,b.m2_t1??null,b.midyear??null,b.m1_t2??null,b.m2_t2??null);
  res.json(calc(db.prepare("SELECT * FROM grades WHERE student_id=?").get(req.params.id)));
});

app.get("/api/attendance",auth,(req,res)=>{
  res.json(db.prepare("SELECT a.*,s.name,s.class_name FROM attendance a JOIN students s ON s.id=a.student_id WHERE a.date=?").all(req.query.date||""));
});
app.post("/api/attendance",auth,(req,res)=>{
  const {date,records}=req.body;
  const q=db.prepare(`INSERT INTO attendance(student_id,date,status) VALUES(?,?,?)
    ON CONFLICT(student_id,date) DO UPDATE SET status=excluded.status`);
  const tx=db.transaction(rs=>rs.forEach(x=>q.run(x.student_id,date,x.status)));
  tx(records||[]);res.json({ok:true});
});

app.get("/api/exams",auth,(req,res)=>res.json(db.prepare("SELECT * FROM exams ORDER BY date,time").all()));
app.post("/api/exams",auth,(req,res)=>{
  const b=req.body; if(!b.class_name||!b.type||!b.date) return res.status(400).json({error:"الصف والنوع والتاريخ مطلوبة"});
  const r=db.prepare("INSERT INTO exams(class_name,type,date,time,note) VALUES(?,?,?,?,?)").run(b.class_name,b.type,b.date,b.time||"",b.note||"");
  res.json(db.prepare("SELECT * FROM exams WHERE id=?").get(r.lastInsertRowid));
});
app.delete("/api/exams/:id",auth,(req,res)=>{db.prepare("DELETE FROM exams WHERE id=?").run(req.params.id);res.json({ok:true})});

app.get("/api/notices",auth,(req,res)=>res.json(db.prepare("SELECT * FROM notices ORDER BY id DESC").all()));
app.post("/api/notices",auth,(req,res)=>{
  const b=req.body; if(!b.class_name||!b.title||!b.body) return res.status(400).json({error:"الصف والعنوان والنص مطلوبة"});
  const r=db.prepare("INSERT INTO notices(class_name,type,title,body,created_at) VALUES(?,?,?,?,datetime('now','localtime'))")
    .run(b.class_name,b.type||"تبليغ عام",b.title,b.body);
  res.json(db.prepare("SELECT * FROM notices WHERE id=?").get(r.lastInsertRowid));
});
app.delete("/api/notices/:id",auth,(req,res)=>{db.prepare("DELETE FROM notices WHERE id=?").run(req.params.id);res.json({ok:true})});

app.get("/api/portal/:code",(req,res)=>{
  const s=db.prepare("SELECT id,name,class_name,code FROM students WHERE code=?").get(req.params.code);
  if(!s) return res.status(404).json({error:"الرمز السري غير صحيح"});
  const g=db.prepare("SELECT * FROM grades WHERE student_id=?").get(s.id)||{};
  const exams=db.prepare("SELECT * FROM exams WHERE class_name=? ORDER BY date,time").all(s.class_name);
  const notices=db.prepare("SELECT * FROM notices WHERE class_name=? OR class_name='جميع الصفوف' ORDER BY id DESC").all(s.class_name);
  const attendance=db.prepare("SELECT date,status FROM attendance WHERE student_id=? ORDER BY date DESC").all(s.id);
  res.json({student:s,grades:calc(g),exams,notices,attendance});
});

app.use((req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
const port=process.env.PORT||3000;
app.listen(port,"0.0.0.0",()=>console.log(`Darajati running on ${port}`));
