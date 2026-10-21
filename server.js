'use strict';
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({limit:'8mb'}));
app.use('/api/login', rateLimit({windowMs: 15*60*1000, max: 30, standardHeaders: true, legacyHeaders: false}));

const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, {recursive:true});
const db = new Database(path.join(dataDir, 'obregon.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','driver')),
 pin_salt TEXT NOT NULL, pin_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, price REAL NOT NULL DEFAULT 0, unit TEXT NOT NULL DEFAULT 'Paquete',
 inventory_type TEXT NOT NULL DEFAULT 'normal', stock REAL NOT NULL DEFAULT 0, photo TEXT, active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sales (
 id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, items_json TEXT NOT NULL, total REAL NOT NULL, payment_method TEXT NOT NULL,
 amount_paid REAL NOT NULL, note TEXT DEFAULT '', created_at TEXT NOT NULL, synced_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS assignments (
 id TEXT PRIMARY KEY, driver_id INTEGER NOT NULL, items_json TEXT NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(driver_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS returns (
 id TEXT PRIMARY KEY, driver_id INTEGER NOT NULL, items_json TEXT NOT NULL, note TEXT DEFAULT '', created_at TEXT NOT NULL,
 FOREIGN KEY(driver_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS movements (
 id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER NOT NULL, user_id INTEGER NOT NULL, kind TEXT NOT NULL,
 quantity REAL NOT NULL, note TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(product_id) REFERENCES products(id), FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
`);
const count = db.prepare('SELECT COUNT(*) n FROM users').get().n;
if (!count) {
 const salt=crypto.randomBytes(16).toString('hex');
 const hash=crypto.scryptSync('2468',salt,64).toString('hex');
 db.prepare('INSERT INTO users(name,role,pin_salt,pin_hash) VALUES(?,?,?,?)').run('Administrador','admin',salt,hash);
}
const scryptHash=(pin,salt)=>crypto.scryptSync(pin,salt,64).toString('hex');
function safeUser(u){return {id:u.id,name:u.name,role:u.role,active:!!u.active};}
function auth(req,res,next){
 const raw=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');
 if(!raw) return res.status(401).json({error:'Inicia sesión nuevamente.'});
 const s=db.prepare('SELECT sessions.user_id, sessions.expires_at, users.* FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=?').get(crypto.createHash('sha256').update(raw).digest('hex'));
 if(!s || s.expires_at<Date.now() || !s.active){ if(s) db.prepare('DELETE FROM sessions WHERE user_id=?').run(s.user_id); return res.status(401).json({error:'Sesión vencida.'});}
 req.user=s; next();
}
const admin=(req,res,next)=>req.user.role==='admin'?next():res.status(403).json({error:'Solo administrador.'});
const id=()=>crypto.randomUUID();
app.post('/api/login',(req,res)=>{
 const pin=String(req.body.pin||'');
 if(!/^\d{4,8}$/.test(pin)) return res.status(400).json({error:'El PIN debe tener entre 4 y 8 dígitos.'});
 const users=db.prepare('SELECT * FROM users WHERE active=1').all();
 let user=null;
 for(const u of users){const candidate=Buffer.from(scryptHash(pin,u.pin_salt),'hex');const expected=Buffer.from(u.pin_hash,'hex');if(candidate.length===expected.length&&crypto.timingSafeEqual(candidate,expected)){user=u;break;}}
 if(!user) return res.status(401).json({error:'PIN incorrecto.'});
 const token=crypto.randomBytes(32).toString('hex');
 db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(crypto.createHash('sha256').update(token).digest('hex'),user.id,Date.now()+7*24*60*60*1000);
 res.json({token,user:safeUser(user)});
});
app.post('/api/logout',auth,(req,res)=>{db.prepare('DELETE FROM sessions WHERE user_id=?').run(req.user.id);res.json({ok:true});});
app.get('/api/me',auth,(req,res)=>res.json({user:safeUser(req.user)}));
app.get('/api/bootstrap',auth,(req,res)=>{
 const products=db.prepare('SELECT * FROM products WHERE active=1 ORDER BY name').all();
 const drivers=db.prepare("SELECT id,name,active FROM users WHERE role='driver' AND active=1 ORDER BY name").all();
 const sales=req.user.role==='admin'
  ? db.prepare('SELECT * FROM sales ORDER BY created_at DESC LIMIT 500').all()
  : db.prepare('SELECT * FROM sales WHERE user_id=? ORDER BY created_at DESC LIMIT 500').all(req.user.id);
 const assignments=req.user.role==='admin'
  ? db.prepare('SELECT * FROM assignments ORDER BY created_at DESC LIMIT 300').all()
  : db.prepare('SELECT * FROM assignments WHERE driver_id=? ORDER BY created_at DESC LIMIT 300').all(req.user.id);
 const returns=req.user.role==='admin'
  ? db.prepare('SELECT * FROM returns ORDER BY created_at DESC LIMIT 300').all()
  : db.prepare('SELECT * FROM returns WHERE driver_id=? ORDER BY created_at DESC LIMIT 300').all(req.user.id);
 const users=req.user.role==='admin'?db.prepare('SELECT id,name,role,active,created_at FROM users ORDER BY role,name').all():[];
 res.json({products,drivers,sales:sales.map(s=>({...s,items:JSON.parse(s.items_json)})),assignments:assignments.map(a=>({...a,items:JSON.parse(a.items_json)})),returns:returns.map(r=>({...r,items:JSON.parse(r.items_json)})),users});
});
app.post('/api/products',auth,admin,(req,res)=>{
 const {name,price,unit='Paquete',inventory_type='normal',stock=0,photo=null}=req.body;
 if(!String(name||'').trim())return res.status(400).json({error:'Escribe el nombre del producto.'});
 if(!Number.isFinite(Number(price))||Number(price)<0||!Number.isFinite(Number(stock))||Number(stock)<0)return res.status(400).json({error:'Precio o existencia inválidos.'});
 const result=db.prepare('INSERT INTO products(name,price,unit,inventory_type,stock,photo) VALUES(?,?,?,?,?,?)').run(String(name).trim(),Number(price),String(unit),String(inventory_type),Number(stock),photo);
 res.json(db.prepare('SELECT * FROM products WHERE id=?').get(result.lastInsertRowid));
});
app.put('/api/products/:id',auth,admin,(req,res)=>{
 const p=db.prepare('SELECT * FROM products WHERE id=?').get(req.params.id);if(!p)return res.status(404).json({error:'Producto no encontrado.'});
 const b=req.body;
 db.prepare('UPDATE products SET name=?,price=?,unit=?,inventory_type=?,stock=?,photo=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?')
 .run(String(b.name??p.name).trim(),Number(b.price??p.price),String(b.unit??p.unit),String(b.inventory_type??p.inventory_type),Number(b.stock??p.stock),b.photo===undefined?p.photo:b.photo,b.active===undefined?p.active:(b.active?1:0),p.id);
 res.json(db.prepare('SELECT * FROM products WHERE id=?').get(p.id));
});
app.post('/api/sales',auth,(req,res)=>{
 const {id:sid=id(),items=[],payment_method='efectivo',amount_paid,total,note='',created_at=new Date().toISOString()}=req.body;
 if(!Array.isArray(items)||!items.length)return res.status(400).json({error:'Agrega al menos un producto.'});
 const sum=items.reduce((s,x)=>s+Math.max(0,Number(x.qty)||0)*Math.max(0,Number(x.price)||0),0);
 if(!Number.isFinite(sum)||Math.abs(sum-Number(total))>0.02)return res.status(400).json({error:'El total no coincide.'});
 const save=db.transaction(()=>{
  for(const x of items){
   const p=db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(Number(x.product_id));
   const qty=Number(x.qty);
   if(!p||!Number.isFinite(qty)||qty<=0)throw Error('Producto o cantidad inválida.');
   if(req.user.role==='admin'){
    if(p.stock<qty)throw Error('Existencia insuficiente: '+p.name);
    db.prepare('UPDATE products SET stock=stock-?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(qty,p.id);
   } else {
    const assignments=db.prepare('SELECT items_json FROM assignments WHERE driver_id=?').all(req.user.id);
    const sold=db.prepare('SELECT items_json FROM sales WHERE user_id=?').all(req.user.id);
    const returned=db.prepare('SELECT items_json FROM returns WHERE driver_id=?').all(req.user.id);
    const totalFor=(rows)=>rows.reduce((acc,row)=>acc+JSON.parse(row.items_json).filter(i=>Number(i.product_id)===p.id).reduce((n,i)=>n+Number(i.qty||0),0),0);
    const available=totalFor(assignments)-totalFor(sold)-totalFor(returned);
    if(available<qty)throw Error('No tienes suficiente inventario asignado de: '+p.name);
   }
   db.prepare("INSERT INTO movements(product_id,user_id,kind,quantity,note) VALUES(?,?,?,?,?)").run(p.id,req.user.id,'venta',-qty,'Venta '+sid);
  }
  db.prepare('INSERT INTO sales(id,user_id,items_json,total,payment_method,amount_paid,note,created_at) VALUES(?,?,?,?,?,?,?,?)').run(sid,req.user.id,JSON.stringify(items),sum,String(payment_method),Number(amount_paid??sum),String(note),String(created_at));
 });try{save();}catch(e){return res.status(400).json({error:e.message});}
 res.json({ok:true,id:sid,total:sum});
});
app.post('/api/assignments',auth,(req,res)=>{
 const {driver_id,items=[]}=req.body;if(req.user.role!=='admin'&&Number(driver_id)!==req.user.id)return res.status(403).json({error:'No puedes asignar mercancía a otro repartidor.'});
 if(req.user.role!=='admin')return res.status(403).json({error:'Solo el administrador asigna mercancía.'});
 if(!Array.isArray(items)||!items.length)return res.status(400).json({error:'Agrega productos.'});
 const aid=id();try{db.transaction(()=>{for(const x of items){const p=db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(Number(x.product_id));if(!p||p.stock<Number(x.qty)||Number(x.qty)<=0)throw Error('Producto o existencia inválida.');db.prepare('UPDATE products SET stock=stock-? WHERE id=?').run(Number(x.qty),p.id);db.prepare("INSERT INTO movements(product_id,user_id,kind,quantity,note) VALUES(?,?,?,?,?)").run(p.id,req.user.id,'asignación',-Number(x.qty),'Asignación '+aid);}db.prepare('INSERT INTO assignments(id,driver_id,items_json,created_at) VALUES(?,?,?,?)').run(aid,Number(driver_id),JSON.stringify(items),new Date().toISOString());})()}catch(e){return res.status(400).json({error:e.message});}
 res.json({ok:true,id:aid});
});
app.post('/api/returns',auth,(req,res)=>{
 const {driver_id,items=[],note='',restock=false}=req.body;const target=Number(driver_id||req.user.id);
 if(req.user.role!=='admin'&&target!==req.user.id)return res.status(403).json({error:'No puedes registrar devoluciones de otra persona.'});
 if(!Array.isArray(items)||!items.length)return res.status(400).json({error:'Agrega productos.'});
 const rid=id();try{db.transaction(()=>{for(const x of items){const p=db.prepare('SELECT * FROM products WHERE id=?').get(Number(x.product_id));if(!p||Number(x.qty)<=0)throw Error('Producto o cantidad inválida.');if(restock)db.prepare('UPDATE products SET stock=stock+? WHERE id=?').run(Number(x.qty),p.id);db.prepare("INSERT INTO movements(product_id,user_id,kind,quantity,note) VALUES(?,?,?,?,?)").run(p.id,req.user.id,restock?'devolución vendible':'devolución no vendible',restock?Number(x.qty):0,String(note));}db.prepare('INSERT INTO returns(id,driver_id,items_json,note,created_at) VALUES(?,?,?,?,?)').run(rid,target,JSON.stringify(items),String(note),new Date().toISOString());})()}catch(e){return res.status(400).json({error:e.message});}
 res.json({ok:true,id:rid});
});
app.post('/api/stock-adjustment',auth,admin,(req,res)=>{
 const {product_id,quantity,note='Ajuste manual'}=req.body;const q=Number(quantity);const p=db.prepare('SELECT * FROM products WHERE id=?').get(Number(product_id));
 if(!p||!Number.isFinite(q)||p.stock+q<0)return res.status(400).json({error:'Producto o cantidad inválida.'});
 db.transaction(()=>{db.prepare('UPDATE products SET stock=stock+?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(q,p.id);db.prepare('INSERT INTO movements(product_id,user_id,kind,quantity,note) VALUES(?,?,?,?,?)').run(p.id,req.user.id,'ajuste',q,String(note));})();
 res.json({ok:true,stock:p.stock+q});
});
app.post('/api/users',auth,admin,(req,res)=>{
 const {name,role='driver',pin}=req.body;
 if(!String(name||'').trim()||!['admin','driver'].includes(role)||!/^\d{4,8}$/.test(String(pin||'')))return res.status(400).json({error:'Nombre, rol o PIN inválido.'});
 const salt=crypto.randomBytes(16).toString('hex');const hash=scryptHash(String(pin),salt);
 try{const r=db.prepare('INSERT INTO users(name,role,pin_salt,pin_hash) VALUES(?,?,?,?)').run(String(name).trim(),role,salt,hash);res.json({id:r.lastInsertRowid,name:String(name).trim(),role,active:1});}catch(e){res.status(400).json({error:'No se pudo crear el usuario. Revisa que el PIN no esté repetido.'});}
});
app.patch('/api/users/:id',auth,admin,(req,res)=>{
 const u=db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);if(!u)return res.status(404).json({error:'Usuario no encontrado.'});
 if(req.body.pin){if(!/^\d{4,8}$/.test(String(req.body.pin)))return res.status(400).json({error:'PIN inválido.'});const salt=crypto.randomBytes(16).toString('hex');db.prepare('UPDATE users SET pin_salt=?,pin_hash=? WHERE id=?').run(salt,scryptHash(String(req.body.pin),salt),u.id);}
 if(req.body.active!==undefined)db.prepare('UPDATE users SET active=? WHERE id=?').run(req.body.active?1:0,u.id);
 if(req.body.name)db.prepare('UPDATE users SET name=? WHERE id=?').run(String(req.body.name).trim(),u.id);
 res.json({ok:true});
});
app.get('/api/reports',auth,(req,res)=>{
 const where=req.user.role==='admin'?'':' WHERE user_id=?';const args=req.user.role==='admin'?[]:[req.user.id];
 const rows=db.prepare('SELECT date(created_at) day, COUNT(*) tickets, SUM(total) sales, SUM(amount_paid) paid FROM sales'+where+' GROUP BY date(created_at) ORDER BY day DESC LIMIT 90').all(...args);
 res.json({daily:rows});
});
app.use(express.static(path.join(__dirname,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
const port=Number(process.env.PORT)||3000;
app.listen(port,()=>console.log(`Tortillería Obregón escuchando en puerto ${port}`));
