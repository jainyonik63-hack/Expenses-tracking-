/* Expense Tracking V4
   Local AES-GCM encryption + optional Firebase Google sign-in
   Cloud backup stores the encrypted record, never the PIN.
*/

const $ = id => document.getElementById(id);
const STORE = 'expense-v3-secure';

let key = null;
let data = null;
let firebaseAuth = null;
let firestore = null;
let cloudEnabled = false;
let cloudAutoSync = false;
let localRecord = null;

const firebaseConfig = {
  apiKey: "PASTE_YOUR_FIREBASE_API_KEY",
  authDomain: "PASTE_YOUR_PROJECT.firebaseapp.com",
  projectId: "PASTE_YOUR_PROJECT_ID",
  appId: "PASTE_YOUR_FIREBASE_APP_ID"
};

const today = () => {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
};

$('txDate').value = today();

function b64(a) {
  return btoa(String.fromCharCode(...new Uint8Array(a)));
}

function un64(s) {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

async function derive(pin, salt) {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(pin),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations:310000, hash:'SHA-256' },
    material,
    { name:'AES-GCM', length:256 },
    false,
    ['encrypt','decrypt']
  );
}

async function encryptData() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(JSON.stringify(data));
  const cipher = await crypto.subtle.encrypt(
    { name:'AES-GCM', iv },
    key,
    plain
  );

  const record = {
    salt: localRecord.salt,
    iv: b64(iv),
    cipher: b64(cipher)
  };

  localRecord = record;
  localStorage.setItem(STORE, JSON.stringify(record));
}

async function save() {
  await encryptData();

  if (cloudAutoSync && firebaseAuth?.currentUser) {
    try {
      await uploadCloud();
    } catch (e) {
      setCloudStatus('Saved on this device. Cloud upload failed.');
    }
  }
}

async function sealNew(pin) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  key = await derive(pin, salt);

  localRecord = { salt:b64(salt) };
  await encryptData();
}

async function decryptRecord(pin, record) {
  const newKey = await derive(pin, un64(record.salt));

  const plain = await crypto.subtle.decrypt(
    { name:'AES-GCM', iv:un64(record.iv) },
    newKey,
    un64(record.cipher)
  );

  return {
    key:newKey,
    data:JSON.parse(new TextDecoder().decode(plain))
  };
}

async function unlock(pin) {
  const record = JSON.parse(localStorage.getItem(STORE));
  const result = await decryptRecord(pin, record);

  key = result.key;
  data = result.data;
  localRecord = record;
  showApp();
}

function age(date) {
  const d = new Date(date+'T00:00:00');
  const n = new Date();
  let a = n.getFullYear()-d.getFullYear();

  if (
    n.getMonth()<d.getMonth() ||
    (n.getMonth()===d.getMonth() && n.getDate()<d.getDate())
  ) a--;

  return a;
}

function money(n) {
  return new Intl.NumberFormat('en-IN', {
    style:'currency',
    currency:'INR'
  }).format(n||0);
}

function err(s) {
  $('authError').textContent = s;
}

function showSetup() {
  $('authTitle').textContent = 'Create your profile';
  $('authDesc').textContent = 'Set up your private expense tracker.';
  $('loginForm').classList.add('hidden');
  $('setupForm').classList.remove('hidden');
}

function showApp() {
  $('auth').classList.add('hidden');
  $('app').classList.remove('hidden');
  $('lockBtn').classList.remove('hidden');
  render();
  updateCloudButtons();
}

function lock() {
  key = null;
  data = null;
  localRecord = null;

  $('app').classList.add('hidden');
  $('auth').classList.remove('hidden');
  $('lockBtn').classList.add('hidden');
  $('loginPin').value = '';

  $('authTitle').textContent = 'Welcome back';
  $('authDesc').textContent = 'Unlock your encrypted expense records.';
  $('loginForm').classList.remove('hidden');
  $('setupForm').classList.add('hidden');
}

if (!localStorage.getItem(STORE)) showSetup();

$('loginForm').onsubmit = async e => {
  e.preventDefault();

  try {
    await unlock($('loginPin').value);
    err('');
  } catch {
    err('Incorrect PIN. Please try again.');
  }
};

$('setupForm').onsubmit = async e => {
  e.preventDefault();

  const pin = $('newPin').value;

  if (!/^\d{6}$/.test(pin)) {
    err('PIN must contain exactly six digits.');
    return;
  }

  if (pin !== $('confirmPin').value) {
    err('PINs do not match.');
    return;
  }

  const f = $('photo').files[0];
  let photo = '';

  if (f) {
    if (f.size > 5*1024*1024) {
      err('Choose a profile image under 5 MB.');
      return;
    }

    photo = await new Promise((resolve,reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = reject;
      r.readAsDataURL(f);
    });
  }

  data = {
    profile:{
      name:$('fullName').value.trim(),
      birth:$('birthDate').value,
      category:$('category').value,
      photo
    },
    transactions:[]
  };

  await sealNew(pin);
  showApp();
};

$('lockBtn').onclick = lock;

/* ---------- Firebase setup ---------- */

function loadScript(src) {
  return new Promise((resolve,reject) => {
    const s = document.createElement('script');
    s.src = src;
    s.onload = resolve;
    s.onerror = reject;
    document.head.appendChild(s);
  });
}

function setCloudStatus(message) {
  const el = $('cloudStatus');
  if (el) el.textContent = message;
}

function createCloudUI() {
  const authPanel = $('auth');

  if (!$('googleSignIn')) {
    const btn = document.createElement('button');
    btn.id = 'googleSignIn';
    btn.type = 'button';
    btn.className = 'secondary';
    btn.style.width = '100%';
    btn.style.marginTop = '10px';
    btn.textContent = 'Sign in with Google';
    btn.onclick = signInGoogle;

    authPanel.appendChild(btn);
  }

  if (!$('cloudStatus')) {
    const status = document.createElement('p');
    status.id = 'cloudStatus';
    status.className = 'muted';
    authPanel.appendChild(status);
  }

  if (!$('cloudPanel')) {
    const panel = document.createElement('div');
    panel.id = 'cloudPanel';
    panel.className = 'panel';

    const heading = document.createElement('h2');
    heading.textContent = 'Cloud backup';

    const status = document.createElement('p');
    status.id = 'cloudAppStatus';
    status.className = 'muted';
    status.textContent = 'Sign in with Google to use cloud backup.';

    const actions = document.createElement('div');
    actions.className = 'actions';

    const upload = document.createElement('button');
    upload.id = 'uploadCloud';
    upload.textContent = 'Back up to cloud';
    upload.onclick = uploadCloud;

    const restore = document.createElement('button');
    restore.id = 'restoreCloud';
    restore.className = 'secondary';
    restore.textContent = 'Restore cloud backup';
    restore.onclick = restoreCloud;

    const signout = document.createElement('button');
    signout.id = 'googleSignOut';
    signout.className = 'secondary';
    signout.textContent = 'Sign out';
    signout.onclick = signOutGoogle;

    actions.append(upload,restore,signout);
    panel.append(heading,status,actions);

    $('app').prepend(panel);
  }
}

async function initFirebase() {
  createCloudUI();

  if (
    !firebaseConfig.apiKey ||
    firebaseConfig.apiKey.startsWith('PASTE_') ||
    !firebaseConfig.projectId ||
    firebaseConfig.projectId.startsWith('PASTE_') ||
    !firebaseConfig.appId ||
    firebaseConfig.appId.startsWith('PASTE_')
  ) {
    setCloudStatus('Add your Firebase web configuration to enable cloud backup.');
    return;
  }

  try {
    await loadScript(
      'https://www.gstatic.com/firebasejs/10.14.1/firebase-app-compat.js'
    );
    await loadScript(
      'https://www.gstatic.com/firebasejs/10.14.1/firebase-auth-compat.js'
    );
    await loadScript(
      'https://www.gstatic.com/firebasejs/10.14.1/firebase-firestore-compat.js'
    );

    if (!firebase.apps.length) firebase.initializeApp(firebaseConfig);

    firebaseAuth = firebase.auth();
    firestore = firebase.firestore();
    cloudEnabled = true;

    firebaseAuth.onAuthStateChanged(user => {
      setCloudStatus(
        user ? `Google account connected: ${user.email}` :
        'Sign in with Google to use cloud backup.'
      );
      updateCloudButtons();
    });

  } catch (e) {
    setCloudStatus('Firebase could not load. Check your internet connection.');
  }
}

async function signInGoogle() {
  if (!cloudEnabled) {
    setCloudStatus('Firebase configuration is not ready yet.');
    return;
  }

  try {
    const provider = new firebase.auth.GoogleAuthProvider();
    await firebaseAuth.signInWithPopup(provider);
    cloudAutoSync = false;
    setCloudStatus('Google sign-in successful. Choose backup or restore.');
    updateCloudButtons();
  } catch (e) {
    setCloudStatus('Google sign-in failed: ' + e.message);
  }
}

async function signOutGoogle() {
  if (!firebaseAuth) return;

  await firebaseAuth.signOut();
  cloudAutoSync = false;
  setCloudStatus('Signed out of Google.');
  updateCloudButtons();
}

function updateCloudButtons() {
  const signedIn = !!firebaseAuth?.currentUser;

  ['uploadCloud','restoreCloud','googleSignOut'].forEach(id => {
    const el = $(id);
    if (el) el.disabled = !signedIn;
  });

  const status = $('cloudAppStatus');

  if (status) {
    status.textContent = signedIn
      ? `Connected as ${firebaseAuth.currentUser.email}`
      : 'Sign in with Google to use cloud backup.';
  }
}

async function uploadCloud() {
  if (!firebaseAuth?.currentUser || !localRecord) {
    setCloudStatus('Sign in and unlock your app before backing up.');
    return;
  }

  try {
    await firestore.collection('users')
      .doc(firebaseAuth.currentUser.uid)
      .set({
        privateBackup:localRecord,
        backupUpdatedAt:firebase.firestore.FieldValue.serverTimestamp()
      }, { merge:true });

    cloudAutoSync = true;
    setCloudStatus('Encrypted backup uploaded successfully.');
    updateCloudButtons();

  } catch (e) {
    setCloudStatus('Cloud backup failed: ' + e.message);
  }
}

async function restoreCloud() {
  if (!firebaseAuth?.currentUser) {
    setCloudStatus('Sign in with Google first.');
    return;
  }

  try {
    const doc = await firestore.collection('users')
      .doc(firebaseAuth.currentUser.uid).get();

    if (!doc.exists || !doc.data().privateBackup) {
      setCloudStatus('No cloud backup was found for this Google account.');
      return;
    }

    if (data && !confirm('Replace the records on this device with the cloud backup?')) {
      return;
    }

    const pin = prompt('Enter the six-digit PIN used when this backup was created.');

    if (pin === null) return;

    if (!/^\d{6}$/.test(pin)) {
      alert('Enter a valid six-digit PIN.');
      return;
    }

    const record = doc.data().privateBackup;
    const result = await decryptRecord(pin,record);

    key = result.key;
    data = result.data;
    localRecord = record;

    localStorage.setItem(STORE,JSON.stringify(record));
    cloudAutoSync = true;

    showApp();
    setCloudStatus('Cloud backup restored successfully.');

  } catch (e) {
    alert('Restore failed. Check your PIN and try again.');
    setCloudStatus('Could not restore the backup.');
  }
}

/* ---------- Transactions and reports ---------- */

function filtered() {
  const p = $('period').value;
  const now = new Date();

  return data.transactions.filter(t =>
    p==='all' ||
    (p==='year'
      ? t.date.slice(0,4)===String(now.getFullYear())
      : t.date.slice(0,7)===today().slice(0,7))
  ).sort((a,b)=>b.date.localeCompare(a.date));
}

function render() {
  const p = data.profile;

  $('displayName').textContent = p.name;
  $('profileMeta').textContent =
    `${p.category} · ${age(p.birth)} years old`;

  $('avatar').src = p.photo ||
    'data:image/svg+xml,' +
    encodeURIComponent(
      '<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80"><rect width="100%" height="100%" fill="#dbeafe"/><text x="50%" y="58%" text-anchor="middle" font-size="34" fill="#1e40af">☺</text></svg>'
    );

  const ts = filtered();
  const inc = ts.filter(t=>t.type==='income')
    .reduce((s,t)=>s+t.amount,0);
  const exp = ts.filter(t=>t.type==='expense')
    .reduce((s,t)=>s+t.amount,0);

  $('incomeTotal').textContent = money(inc);
  $('expenseTotal').textContent = money(exp);
  $('balanceTotal').textContent = money(inc-exp);

  $('transactions').innerHTML = '';

  if (!ts.length) {
    $('transactions').innerHTML =
      '<p class="muted">No transactions in this period yet.</p>';
  }

  for (const t of ts) {
    const el = document.createElement('div');
    el.className = 'tx';

    const left = document.createElement('div');
    const right = document.createElement('div');

    const title = document.createElement('strong');
    title.textContent = t.description;

    const meta = document.createElement('div');
    meta.className = 'muted';
    meta.textContent = `${t.category} · ${t.date}`;

    left.append(title,meta);

    const amount = document.createElement('strong');
    amount.className = t.type;
    amount.textContent =
      (t.type==='income'?'+':'−')+money(t.amount);

    const actions = document.createElement('div');
    actions.className = 'actions';
    actions.style.justifyContent = 'flex-end';
    actions.style.marginTop = '5px';

    const edit = document.createElement('button');
    edit.className = 'secondary';
    edit.textContent = 'Edit';
    edit.onclick = () => editTx(t.id);

    const del = document.createElement('button');
    del.className = 'danger';
    del.textContent = 'Delete';
    del.onclick = () => deleteTx(t.id);

    actions.append(edit,del);
    right.append(amount,actions);
    el.append(left,right);

    $('transactions').append(el);
  }

  drawChart(ts);
  fillYears();
  updateReport();
}

function resetForm() {
  $('txForm').reset();
  $('txId').value = '';
  $('txDate').value = today();
  $('cancelEdit').classList.add('hidden');
  $('saveTx').textContent = 'Save transaction';
}

$('txForm').onsubmit = async e => {
  e.preventDefault();

  const id = $('txId').value || crypto.randomUUID();

  const t = {
    id,
    description:$('description').value.trim(),
    amount:Number($('amount').value),
    type:$('type').value,
    category:$('txCategory').value,
    date:$('txDate').value
  };

  const i = data.transactions.findIndex(x=>x.id===id);

  if (i<0) data.transactions.push(t);
  else data.transactions[i] = t;

  await save();
  resetForm();
  render();
};

function editTx(id) {
  const t = data.transactions.find(x=>x.id===id);

  $('txId').value = t.id;
  $('description').value = t.description;
  $('amount').value = t.amount;
  $('type').value = t.type;
  $('txCategory').value = t.category;
  $('txDate').value = t.date;

  $('cancelEdit').classList.remove('hidden');
  $('saveTx').textContent = 'Update transaction';

  window.scrollTo({top:0,behavior:'smooth'});
}

async function deleteTx(id) {
  if (!confirm('Delete this transaction?')) return;

  data.transactions = data.transactions.filter(x=>x.id!==id);
  await save();
  render();
}

$('cancelEdit').onclick = resetForm;
$('period').onchange = render;

function drawChart(ts) {
  const sums = {};

  ts.filter(t=>t.type==='expense').forEach(t => {
    sums[t.category] = (sums[t.category]||0)+t.amount;
  });

  const c = $('chart');
  const ctx = c.getContext('2d');

  ctx.clearRect(0,0,c.width,c.height);

  const entries = Object.entries(sums)
    .sort((a,b)=>b[1]-a[1]);

  if (!entries.length) {
    ctx.fillStyle = '#64748b';
    ctx.font = '18px sans-serif';
    ctx.fillText('No expense data yet',20,45);
    $('chartLegend').textContent = '';
    return;
  }

  const max = entries[0][1];
  const barH = Math.min(38,220/entries.length);

  entries.slice(0,7).forEach(([name,val],i) => {
    const y = 12+i*barH*1.25;

    ctx.fillStyle = '#334155';
    ctx.font = '15px sans-serif';
    ctx.fillText(name,8,y+15);

    ctx.fillStyle = '#3b82f6';
    ctx.fillRect(125,y,Math.max(2,350*val/max),19);

    ctx.fillStyle = '#334155';
    ctx.font = '13px sans-serif';
    ctx.fillText(
      money(val),
      Math.min(480,132+350*val/max),
      y+15
    );
  });

  $('chartLegend').textContent =
    `${entries.length} expense categories · top 7 shown`;
}

function fillYears() {
  const y = $('reportYear');
  const old = y.value;

  const years = [...new Set([
    new Date().getFullYear(),
    ...data.transactions.map(t=>Number(t.date.slice(0,4)))
  ])].sort((a,b)=>b-a);

  y.innerHTML = years.map(v=>`<option>${v}</option>`).join('');

  if (years.includes(Number(old))) y.value = old;
}

function reportRows() {
  const y = $('reportYear').value;
  const m = $('reportMonth').value;

  return data.transactions.filter(t =>
    t.date.slice(0,4)===y &&
    (m==='all' || Number(t.date.slice(5,7))-1===Number(m))
  ).sort((a,b)=>a.date.localeCompare(b.date));
}

function updateReport() {
  if (!$('reportYear').value) return;

  const a = reportRows();
  const i = a.filter(t=>t.type==='income')
    .reduce((s,t)=>s+t.amount,0);
  const e = a.filter(t=>t.type==='expense')
    .reduce((s,t)=>s+t.amount,0);

  $('reportSummary').textContent =
    `${a.length} transactions · Income ${money(i)} · Expenses ${money(e)} · Net ${money(i-e)}`;
}

$('reportYear').onchange = updateReport;
$('reportMonth').onchange = updateReport;

$('csvBtn').onclick = () => {
  const rows = [
    ['Date','Description','Type','Category','Amount (INR)'],
    ...reportRows().map(t=>[
      t.date,t.description,t.type,t.category,t.amount
    ])
  ];

  const csv = rows.map(r =>
    r.map(v=>'"'+String(v).replaceAll('"','""')+'"').join(',')
  ).join('\r\n');

  download(
    new Blob(['\ufeff'+csv],{type:'text/csv;charset=utf-8'}),
    `expense-report-${$('reportYear').value}-${$('reportMonth').value}.csv`
  );
};

$('pdfBtn').onclick = () => {
  const rows = reportRows();
  const w = window.open('','_blank');

  if (!w) {
    alert('Allow pop-ups to print the report.');
    return;
  }

  const esc = s => String(s).replace(/[&<>"]/g,c=>({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'
  }[c]));

  w.document.write(`
    <title>Expense report</title>
    <h1>Expense report</h1>
    <p>${$('reportYear').value} · ${$('reportMonth').selectedOptions[0].text}</p>
    <table border="1" cellpadding="8" cellspacing="0">
      <tr><th>Date</th><th>Description</th><th>Type</th><th>Category</th><th>Amount (INR)</th></tr>
      ${rows.map(t=>`
        <tr>
          <td>${esc(t.date)}</td>
          <td>${esc(t.description)}</td>
          <td>${esc(t.type)}</td>
          <td>${esc(t.category)}</td>
          <td>${t.amount.toFixed(2)}</td>
        </tr>
      `).join('')}
    </table>
  `);

  w.document.close();
  w.print();
};

function download(blob,name) {
  const a = document.createElement('a');
  const url = URL.createObjectURL(blob);

  a.href = url;
  a.download = name;
  a.click();

  setTimeout(()=>URL.revokeObjectURL(url),1000);
}

$('editProfile').onclick = async () => {
  const name = prompt('Full name',data.profile.name);
  if (name===null) return;

  const category = prompt(
    'Category: Student, Business, Trader or Teenager',
    data.profile.category
  );

  if (category===null) return;

  if (!['Student','Business','Trader','Teenager'].includes(category)) {
    alert('Choose one of the listed categories.');
    return;
  }

  data.profile.name = name.trim();
  data.profile.category = category;

  await save();
  render();
};

if ('serviceWorker' in navigator) {
  window.addEventListener('load',() => {
    navigator.serviceWorker.register('./sw.js').catch(()=>{});
  });
}

initFirebase();
