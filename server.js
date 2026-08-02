import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { join, dirname, } from "path";

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

fastify.post("/register", async(req,res)=>{
    return res.code(418).send("not implemented")
})

fastify.post('/check-txt-record',async(req,res)=>{
    try{
    const txt = await resolveTxt("_ubgchat."+req.body.domainName);
    console.log(txt);
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
// how do i start the server
fastify.listen({ port: 3000, host: "0.0.0.0" });
