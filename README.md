# 🚛 Karolinska Truckers – Server

## Deploy på Railway (gratis, 5 minuter)

### 1. Lägg upp koden på GitHub
```bash
cd truckers-server
git init
git add .
git commit -m "first commit"
# Skapa ett nytt repo på github.com, kopiera URL:en, sedan:
git remote add origin https://github.com/DITTNAMN/truckers-server.git
git push -u origin main
```

### 2. Deploya på Railway
1. Gå till **railway.app** och logga in med GitHub
2. Klicka **New Project → Deploy from GitHub repo**
3. Välj ditt repo
4. Railway hittar `package.json` automatiskt och startar servern

### 3. Sätt miljövariabler på Railway
Under fliken **Variables** i Railway, lägg till:
```
JWT_SECRET = valfritt-langt-hemligt-ord-t-ex-truckers2025karolinska
```
(PORT sätts automatiskt av Railway)

### 4. Klar!
Railway ger dig en URL som `https://truckers-server-production.up.railway.app`
Dela den med kollegorna – alla loggar in och ser varandras status i realtid.

---

## Lokal körning (för test)
```bash
npm install
node server.js
# Öppna http://localhost:3000
```

## Funktioner
- Skapa konto / logga in
- Alla statusändringar (pågående / klar) synkas till alla i realtid (var 8:e sekund)
- SQLite-databas sparas på servern
- JWT-tokens, lösenord hashade med bcrypt
