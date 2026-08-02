import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { join, dirname, } from "path";

const fastify = Fastify({ forceCloseConnections: true, trustProxy: true });

fastify.register(fastifyStatic, {
    root: join(import.meta.dirname, "public"),
});
fastify.get("/ping", async (req, res) => {
    res.send("ponk.");
});
// how do i start the server
fastify.listen({ port: 3000, host: "0.0.0.0" });
