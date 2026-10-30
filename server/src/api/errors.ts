import type { FastifyReply } from "fastify";

/** The only error shape the API returns: `{ error: { code, message } }` with fixed, non-echoing messages. */
export function sendError(reply: FastifyReply, status: number, code: string, message: string) {
  return reply.code(status).type("application/json").send({ error: { code, message } });
}
