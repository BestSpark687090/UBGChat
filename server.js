import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { join, dirname, } from "path";
import { readFile, writeFile } from "fs/promises";
//#region ai registration section
// Written by AI because IDK how to do hashing... also it's 11:58 at night while I write this.
import { randomBytes, scrypt, timingSafeEqual } from "crypto";
import { promisify } from "util";
const scryptAsync = promisify(scrypt);

const USERS_FILE = join(import.meta.dirname, "users.json");

// token -> username. In-memory only, resets on restart (so does everyone's login).
const sessions = new Map();

function parseCookies(header) {
    const out = {};
    if (!header) return out;
    for (const part of header.split(";")) {
        const idx = part.indexOf("=");
        if (idx === -1) continue;
        out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
    }
    return out;
}

function getSessionUsername(req) {
    const token = parseCookies(req.headers.cookie).session;
    return token ? sessions.get(token) : undefined;
}

async function loadUsers() {
    let raw;
    try {
        raw = await readFile(USERS_FILE, "utf-8");
    } catch (e) {
        if (e.code === "ENOENT") return {};
        throw e;
    }
    return raw.trim() ? JSON.parse(raw) : {};
}

async function saveUsers(users) {
    await writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

async function hashPassword(password) {
    const salt = randomBytes(16).toString("hex");
    const derived = await scryptAsync(password, salt, 64);
    return `${salt}:${derived.toString("hex")}`;
}

async function verifyPassword(password, stored) {
    const [salt, hash] = stored.split(":");
    const hashBuf = Buffer.from(hash, "hex");
    const derived = await scryptAsync(password, salt, hashBuf.length);
    return timingSafeEqual(hashBuf, derived);
}
//#endregion ai registration section

// #region ai code for dns lookup 
// Raw DNS (port 53) is blocked in this... for some reason, so we resolve over
// DNS-over-HTTPS instead - same result, just tunneled through normal HTTPS.
async function dohQuery(name, type) {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
    const res = await fetch(url, { headers: { accept: "application/dns-json" } });
    const data = await res.json();
    if (data.Status === 3) {
        const e = new Error(`${type} ENOTFOUND ${name}`);
        e.code = "ENOTFOUND";
        throw e;
    }
    return (data.Answer || []).filter(a => a.type === (type === "TXT" ? 16 : 1));
}

async function resolve4(hostname) {
    const answers = await dohQuery(hostname, "A");
    return answers.map(a => a.data);
}

async function resolveTxt(hostname) {
    const answers = await dohQuery(hostname, "TXT");
    // TXT records come back as quoted, possibly multi-chunk strings, e.g. "\"foo\" \"bar\""
    return answers.map(a => [...a.data.matchAll(/"([^"]*)"/g)].map(m => m[1]));
}
//#endregion ai code for dns lookup


const fastify = Fastify({ forceCloseConnections: true, trustProxy: true });

fastify.register(fastifyStatic, {
    root: join(import.meta.dirname, "public"),
});
fastify.get("/ping", async (req, res) => {
    res.send("ponk.");
});

fastify.post("/check-ubg-domain", async (req, res) => {
    console.log("Asked to check", req.body);
    // const resp = await fetch(req.body.domain);
    try{
        const addrs = await resolve4(new URL(req.body.domain).hostname)
        return res.code(200).send("Domain is valid.");
    }catch(e){
        if (e.code === 'ENOTFOUND') {
        return res.code(404).send("Domain doesn't exist.")
        }
    }
})

// ai generated registration section...
fastify.post("/register", async(req,res)=>{
    const { domainName, username, password } = req.body;
    if(!domainName || !username || !password){
        return res.code(400).send("Missing domainName, username, or password.");
    }
    const users = await loadUsers();
    if(users[username]){
        return res.code(409).send("That username is already registered.");
    }
    users[username] = { domainName, password: await hashPassword(password) };
    await saveUsers(users);
    return res.code(200).send("Registered!");
})
// and login section...
fastify.post("/login", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.code(400).send("Missing username or password.");
    }
    const users = await loadUsers();
    const user = users[username];
    if (!user || !(await verifyPassword(password, user.password))) {
        return res.code(401).send("Invalid username or password.");
    }
    const token = randomBytes(32).toString("hex");
    sessions.set(token, username);
    res.header("Set-Cookie", `session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800`);
    return res.code(200).send("Logged in!");
});
// and this too
fastify.get("/me", async (req, res) => {
    const username = getSessionUsername(req);
    if (!username) {
        return res.code(401).send("Not logged in.");
    }
    return res.code(200).send(username);
});

// The username goes back to the client to be placed into /register later btw :)
fastify.post('/check-txt-record',async(req,res)=>{
    try{
    const txt = await resolveTxt("_ubgchat."+req.body.domainName);
    // console.log(txt);
    // TXT records are held like this: [ [ 'Username' ] ]
    // Weird, i know.
    if(txt[0][0].trim()!=""){
        return res.code(200).send(txt[0][0].trim())
    }else{
        return res.code(404).send("TXT record visible, but you can't have an empty username!")
    }
    }catch(e){
        return res.code(404).send("TXT record not visible yet."+e.message)
    }
})
fastify.post('/check-file',async(req,res)=>{
    try{
    const resp = await fetch(`https://${req.body.domainName}/.well-known/ubgchat`);
    const txt = await resp.text();
    // console.log(txt);
    if(txt.trim()!=""){
        return res.code(200).send(txt.trim())
    }else{
        return res.code(404).send("File visible, but you can't have an empty username!")
    }
    }catch(e){
        console.log(e)
        return res.code(404).send("Domain doesn't seem to be active. Weird. I got a "+res.statusCode+" when trying to use.")
    }
})
fastify.listen({ port: 3000, host: "0.0.0.0" });
