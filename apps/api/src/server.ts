import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { PrismaClient } from "@prisma/client";

dotenv.config();
const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(helmet());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "dev";

function signToken(payload: any) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "15m" });
}

function authRequired(req: any, res: any, next: any) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "invalid_token" });
  }
}

async function vipRequired(req: any, res: any, next: any) {
  const userId = req.user?.sub;
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (user.banned) return res.status(403).json({ error: "banned" });
  req.dbUser = user;
  next();
}

const RegisterSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  invite_code: z.string().min(6)
});

app.post("/auth/register", async (req, res) => {
  const parsed = RegisterSchema.safeParse(req.body);

  const { email, password, invite_code } = parsed.data;

  const inv = await prisma.invite.findUnique({ where: { code: invite_code } });
  if (inv.usedCount >= inv.maxUses) return res.status(403).json({ error: "invite_used" });
  if (new Date(inv.expiresAt).getTime() < Date.now()) return res.status(403).json({ error: "invite_expired" });

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) return res.status(409).json({ error: "email_exists" });

  const passwordHash = await bcrypt.hash(password, 12);

  const user = await prisma.user.create({
    data: {
      email,
      passwordHash,
      invitedAt: new Date(),
      vipTier: inv.tierGranted,
      vipActive: false,
      role: "SUBSCRIBER"
    }
  });

  await prisma.invite.update({
    where: { code: invite_code },
    data: { usedCount: inv.usedCount + 1 }
  });

  const token = signToken({ sub: user.id, role: user.role });
  res.json({ token, user: { id: user.id, email: user.email, vipActive: user.vipActive, vipTier: user.vipTier } });
});

const LoginSchema = z.object({ email: z.string().email(), password: z.string().min(1) });

app.post("/auth/login", async (req, res) => {
  const parsed = LoginSchema.safeParse(req.body);
  const { email, password } = parsed.data;

  const user = await prisma.user.findUnique({ where: { email } });

  const ok = await bcrypt.compare(password, user.passwordHash);

  const token = signToken({ sub: user.id, role: user.role });
  res.json({ token, user: { id: user.id, email: user.email, vipActive: user.vipActive, vipTier: user.vipTier } });
});

// ADMIN: create invites
app.post("/admin/invites", authRequired, async (req: any, res) => {
  const me = await prisma.user.findUnique({ where: { id: req.user.sub } });

  const body = z.object({
    code: z.string().min(6),
    maxUses: z.number().int().min(1).max(100).default(1),
    expiresAt: z.string(),
    tierGranted: z.enum(["VIP_BASIC","VIP_PLUS","VIP_ELITE"]).default("VIP_BASIC")
  }).parse(req.body);

  const inv = await prisma.invite.create({
    data: { code: body.code, maxUses: body.maxUses, expiresAt: new Date(body.expiresAt), tierGranted: body.tierGranted }
  });

  res.json(inv);
});

// ADMIN: activate VIP (later becomes payment webhook)
app.post("/admin/vip/activate", authRequired, async (req: any, res) => {
  const me = await prisma.user.findUnique({ where: { id: req.user.sub } });

  const body = z.object({ userId: z.string(), tier: z.enum(["VIP_BASIC","VIP_PLUS","VIP_ELITE"]) }).parse(req.body);
  const user = await prisma.user.update({
    where: { id: body.userId },
    data: { vipActive: true, vipTier: body.tier }
  });
  res.json({ ok: true, user: { id: user.id, vipActive: user.vipActive, vipTier: user.vipTier } });
});

// VIP: list rooms
app.get("/vip/rooms", authRequired, vipRequired, async (_req: any, res) => {
  const rooms = await prisma.room.findMany({ orderBy: { createdAt: "desc" } });
  res.json({ rooms });
});

// VIP: mint a room token (stub for LiveKit/Daily/Agora)
app.post("/vip/rooms/:roomId/token", authRequired, vipRequired, async (req: any, res) => {
  const { roomId } = req.params;
  const room = await prisma.room.findUnique({ where: { id: roomId } });

  const order: Record<string, number> = { VIP_BASIC: 1, VIP_PLUS: 2, VIP_ELITE: 3 };
  if (order[req.dbUser.vipTier] < order[room.requiredTier]) return res.status(403).json({ error: "tier_too_low" });

  // Replace this with provider token minting when you choose LiveKit/Daily/Agora
  res.json({ roomId, provider: "TBD", joinToken: "REPLACE_WITH_PROVIDER_TOKEN", expiresInSeconds: 120 });
});

app.get("/health", (_req, res) => res.json({ ok: true }));

const port = Number(process.env.PORT || 4000);
app.listen(port, () => console.log(`API running on http://localhost:${port}`));
