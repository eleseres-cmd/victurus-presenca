// Presença do Colaborador · Victurus — API (Netlify Functions + Netlify Blobs)
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api/*" };

const TZ = "America/Sao_Paulo";
const EQUIPE_INICIAL = {
  "Juliana": [],
  "Miguel Peixoto": [{ dia: 2, hora: "19:15" }, { dia: 4, hora: "19:15" }],
  "Camila": [],
  "Luana": [{ dia: 1, hora: "19:15" }, { dia: 3, hora: "19:15" }, { dia: 5, hora: "19:15" }],
  "Amanda": [{ dia: 2, hora: "19:15" }, { dia: 4, hora: "19:15" }],
  "João Miguel": [{ dia: 2, hora: "19:15" }, { dia: 4, hora: "19:15" }],
};

const store = () => getStore({ name: "presenca-victurus", consistency: "strong" });
const get = (k) => store().get(k, { type: "json" });
const put = (k, v) => store().setJSON(k, v);
const del = (k) => store().delete(k);
const slug = (s) => String(s).normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "x";

/* ---------- Tempo em Brasília ---------- */
function agoraSP() {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-CA", {
    timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false, weekday: "short",
  }).formatToParts(new Date()).map((x) => [x.type, x.value]));
  const dias = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  const hh = p.hour === "24" ? "00" : p.hour;
  return { data: `${p.year}-${p.month}-${p.day}`, hora: `${hh}:${p.minute}`, dia: dias[p.weekday] };
}
const minutos = (h) => { const [a, b] = String(h).split(":").map(Number); return (a || 0) * 60 + (b || 0); };

/* ---------- Senhas e tokens ---------- */
function hashSenha(senha, salt) { return crypto.scryptSync(String(senha), salt, 32).toString("hex"); }
function novaCredencial(senha) { const salt = crypto.randomBytes(12).toString("hex"); return { salt, hash: hashSenha(senha, salt) }; }
function confere(senha, cred) {
  if (!cred || !cred.hash) return false;
  const a = Buffer.from(hashSenha(senha, cred.salt), "hex"), b = Buffer.from(cred.hash, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
async function segredo() {
  let s = await get("segredo");
  if (!s) { s = { v: crypto.randomBytes(32).toString("hex") }; await put("segredo", s); }
  return s.v;
}
async function criarToken(dados) {
  const corpo = Buffer.from(JSON.stringify({ ...dados, exp: Date.now() + 90 * 864e5 })).toString("base64url");
  const sig = crypto.createHmac("sha256", await segredo()).update(corpo).digest("base64url");
  return `${corpo}.${sig}`;
}
async function lerToken(req) {
  const t = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const [corpo, sig] = t.split(".");
  if (!corpo || !sig) return null;
  const esperado = crypto.createHmac("sha256", await segredo()).update(corpo).digest("base64url");
  if (sig.length !== esperado.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(esperado))) return null;
  try { const d = JSON.parse(Buffer.from(corpo, "base64url").toString()); return d.exp > Date.now() ? d : null; } catch { return null; }
}

/* Bloqueio após muitas tentativas erradas */
async function bloqueado(chave) { const l = await get(`lock/${chave}`); return l && l.ate > Date.now(); }
async function errou(chave) {
  const l = (await get(`lock/${chave}`)) || { n: 0, ate: 0 };
  l.n = (l.ate && l.ate < Date.now()) ? 1 : l.n + 1;
  if (l.n >= 8) { l.ate = Date.now() + 15 * 60e3; l.n = 0; }
  await put(`lock/${chave}`, l);
}
const acertou = (chave) => del(`lock/${chave}`);

/* ---------- Dados ---------- */
async function colabs() {
  let c = await get("colabs");
  if (!c) {
    c = {};
    for (const [nome, agenda] of Object.entries(EQUIPE_INICIAL)) c[nome] = { agenda, cred: null };
    await put("colabs", c);
  }
  return c;
}
async function configApp() { return { valor: 10, ...((await get("config")) || {}) }; }
const aulasDe = async (nome) => (await get(`aulas/${slug(nome)}`)) || [];
const confsDe = async (nome) => (await get(`conf/${slug(nome)}`)) || {};
const pixDe = async (nome) => ((await get(`pix/${slug(nome)}`)) || {}).pix || "";
const pagamentos = async () => (await get("pagamentos")) || [];
function pagasSet(pags) { const s = new Set(); pags.forEach((p) => (p.aulaIds || []).forEach((id) => s.add(p.nome + "|" + id))); return s; }

/* ---------- Respostas ---------- */
const json = (d, status = 200) => new Response(JSON.stringify(d), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const erro = (msg, status = 400) => json({ erro: msg }, status);

export default async (req) => {
  try {
    const url = new URL(req.url);
    const rota = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
    const metodo = req.method;
    const corpo = metodo === "POST" ? await req.json().catch(() => ({})) : {};

    /* ----- Público ----- */
    if (rota === "publico") {
      const admin = await get("admin");
      return json({ setup: !admin, equipe: Object.keys(await colabs()) });
    }
    if (rota === "setup" && metodo === "POST") {
      if (await get("admin")) return erro("O administrador já foi criado.", 403);
      const senha = String(corpo.senha || "");
      if (senha.length < 6) return erro("Use pelo menos 6 caracteres.");
      await put("admin", novaCredencial(senha));
      return json({ token: await criarToken({ papel: "admin" }) });
    }
    if (rota === "login" && metodo === "POST") {
      const nome = String(corpo.nome || ""), senha = String(corpo.senha || "");
      const c = (await colabs())[nome];
      if (!c) return erro("Colaborador não encontrado.", 404);
      if (!c.cred) return erro("Sua senha ainda não foi criada. Fale com o Eleser.", 403);
      if (await bloqueado(slug(nome))) return erro("Muitas tentativas. Espere 15 minutos.", 429);
      if (!confere(senha, c.cred)) { await errou(slug(nome)); return erro("Senha incorreta.", 401); }
      await acertou(slug(nome));
      return json({ token: await criarToken({ papel: "colab", nome, v: c.cred.salt }) });
    }
    if (rota === "admin-login" && metodo === "POST") {
      if (await bloqueado("admin")) return erro("Muitas tentativas. Espere 15 minutos.", 429);
      if (!confere(String(corpo.senha || ""), await get("admin"))) { await errou("admin"); return erro("Senha incorreta.", 401); }
      await acertou("admin");
      return json({ token: await criarToken({ papel: "admin" }) });
    }

    const eu = await lerToken(req);
    if (!eu) return erro("Entre de novo.", 401);

    /* ----- Colaborador ----- */
    if (eu.papel === "colab") {
      const todos = await colabs();
      const c = todos[eu.nome];
      if (!c || !c.cred || c.cred.salt !== eu.v) return erro("Entre de novo.", 401);
      const agora = agoraSP();

      if (rota === "eu") {
        const [aulas, confs, pix, pags, cfg] = await Promise.all([aulasDe(eu.nome), confsDe(eu.nome), pixDe(eu.nome), pagamentos(), configApp()]);
        return json({ nome: eu.nome, agenda: c.agenda || [], aulas, confs, pix, valor: cfg.valor, agora,
          pagas: [...pagasSet(pags)].filter((k) => k.startsWith(eu.nome + "|")).map((k) => k.slice(eu.nome.length + 1)),
          recebido: pags.filter((p) => p.nome === eu.nome).reduce((t, p) => t + (p.total || 0), 0) });
      }
      if (rota === "validar" && metodo === "POST") {
        const aulas = await aulasDe(eu.nome);
        let reg;
        if (corpo.extra) {
          reg = { id: `${agora.data}_extra-${agora.hora.replace(":", "")}`, data: agora.data, hora: agora.hora, extra: true, status: "ok" };
        } else {
          const h = String(corpo.hora || "");
          const slot = (c.agenda || []).find((a) => Number(a.dia) === agora.dia && a.hora === h);
          if (!slot) return erro("Não há aula sua neste horário hoje.");
          if (minutos(agora.hora) < minutos(h) - 60) return erro("A validação libera 1 hora antes da aula.");
          reg = { id: `${agora.data}_${h.replace(":", "")}`, data: agora.data, hora: agora.hora, horaAula: h, status: "ok" };
        }
        if (aulas.some((a) => a.id === reg.id)) return erro("Essa aula já foi validada.");
        reg.em = new Date().toISOString();
        aulas.push(reg);
        await put(`aulas/${slug(eu.nome)}`, aulas);
        return json({ ok: true, aula: reg });
      }
      if (rota === "confirmar" && metodo === "POST") {
        const confs = await confsDe(eu.nome);
        const id = String(corpo.id || "").slice(0, 40);
        if (!/^\d{4}-\d{2}-\d{2}_\d{4}$/.test(id)) return erro("Aula inválida.");
        confs[id] = { resposta: corpo.resposta === "nao" ? "nao" : "vou", motivo: String(corpo.motivo || "").slice(0, 140), em: new Date().toISOString() };
        const limite = somaDias(agora.data, -40);
        for (const k of Object.keys(confs)) if (k.slice(0, 10) < limite) delete confs[k];
        await put(`conf/${slug(eu.nome)}`, confs);
        return json({ ok: true });
      }
      if (rota === "pix" && metodo === "POST") {
        const pix = String(corpo.pix || "").trim().slice(0, 120);
        if (!pix) return erro("Digite sua chave Pix.");
        await put(`pix/${slug(eu.nome)}`, { pix, em: new Date().toISOString() });
        return json({ ok: true });
      }
      return erro("Rota não encontrada.", 404);
    }

    /* ----- Administrador ----- */
    if (eu.papel !== "admin") return erro("Sem permissão.", 403);
    const todos = await colabs();

    if (rota === "admin") {
      const nomes = Object.keys(todos);
      const [cfg, pags, ...por] = await Promise.all([configApp(), pagamentos(),
        ...nomes.map(async (n) => ({ n, aulas: await aulasDe(n), confs: await confsDe(n), pix: await pixDe(n) }))]);
      const equipe = {};
      por.forEach(({ n, aulas, confs, pix }) => { equipe[n] = { agenda: todos[n].agenda || [], temSenha: !!todos[n].cred, aulas, confs, pix }; });
      return json({ config: cfg, equipe, pagamentos: pags, agora: agoraSP() });
    }
    if (rota === "admin/pagar" && metodo === "POST") {
      const nome = String(corpo.nome || "");
      if (!todos[nome]) return erro("Colaborador não encontrado.");
      const [aulas, pags, cfg] = await Promise.all([aulasDe(nome), pagamentos(), configApp()]);
      const pagas = pagasSet(pags);
      const ids = aulas.filter((a) => a.status !== "recusada" && !pagas.has(nome + "|" + a.id)).map((a) => a.id);
      if (!ids.length) return erro("Nada a pagar para esse colaborador.");
      const p = { id: crypto.randomUUID(), nome, aulaIds: ids, qtd: ids.length, valorUnit: cfg.valor, total: ids.length * cfg.valor,
        forma: String(corpo.forma || "Pix").slice(0, 20), obs: String(corpo.obs || "").slice(0, 140), data: agoraSP().data, em: new Date().toISOString() };
      pags.push(p); await put("pagamentos", pags);
      return json({ ok: true, pagamento: p });
    }
    if (rota === "admin/pagamento-manual" && metodo === "POST") {
      const nome = String(corpo.nome || "");
      if (!todos[nome]) return erro("Colaborador não encontrado.");
      const qtd = Math.max(0, Math.floor(Number(corpo.qtd) || 0)), valorUnit = Math.max(0, Number(corpo.valorUnit) || 0);
      if (!qtd || !valorUnit) return erro("Informe a quantidade de aulas e o valor.");
      const pags = await pagamentos();
      const p = { id: crypto.randomUUID(), nome, aulaIds: [], qtd, valorUnit, total: qtd * valorUnit, manual: true,
        forma: String(corpo.forma || "Pix").slice(0, 20), obs: String(corpo.obs || "").slice(0, 140), data: agoraSP().data, em: new Date().toISOString() };
      pags.push(p); await put("pagamentos", pags);
      return json({ ok: true, pagamento: p });
    }
    if (rota === "admin/desfazer" && metodo === "POST") {
      const pags = await pagamentos();
      await put("pagamentos", pags.filter((p) => p.id !== corpo.id));
      return json({ ok: true });
    }
    if (rota === "admin/aula" && metodo === "POST") {
      const nome = String(corpo.nome || "");
      const aulas = await aulasDe(nome);
      const a = aulas.find((x) => x.id === corpo.id);
      if (!a) return erro("Aula não encontrada.");
      a.status = corpo.status === "recusada" ? "recusada" : "ok";
      await put(`aulas/${slug(nome)}`, aulas);
      return json({ ok: true });
    }
    if (rota === "admin/lancar-aula" && metodo === "POST") {
      const nome = String(corpo.nome || ""), data = String(corpo.data || ""), hora = String(corpo.hora || "");
      if (!todos[nome]) return erro("Colaborador não encontrado.");
      if (!/^\d{4}-\d{2}-\d{2}$/.test(data) || !/^\d{2}:\d{2}$/.test(hora)) return erro("Data ou hora inválida.");
      const aulas = await aulasDe(nome);
      const id = `${data}_${hora.replace(":", "")}`;
      if (aulas.some((a) => a.id === id)) return erro("Essa aula já está lançada.");
      aulas.push({ id, data, hora, horaAula: hora, status: "ok", lancadaPeloAdmin: true, em: new Date().toISOString() });
      await put(`aulas/${slug(nome)}`, aulas);
      return json({ ok: true });
    }
    if (rota === "admin/config" && metodo === "POST") {
      const v = Number(String(corpo.valor).replace(",", "."));
      if (!(v > 0)) return erro("Valor inválido.");
      await put("config", { ...(await configApp()), valor: v });
      return json({ ok: true });
    }
    if (rota === "admin/colab" && metodo === "POST") {
      const nome = String(corpo.nome || "").trim().slice(0, 40);
      if (!nome) return erro("Digite o nome.");
      const agenda = (Array.isArray(corpo.agenda) ? corpo.agenda : [])
        .filter((a) => a && /^\d{2}:\d{2}$/.test(a.hora) && Number(a.dia) >= 0 && Number(a.dia) <= 6)
        .map((a) => ({ dia: Number(a.dia), hora: a.hora })).slice(0, 21);
      todos[nome] = { cred: (todos[nome] && todos[nome].cred) || null, agenda };
      await put("colabs", todos);
      return json({ ok: true });
    }
    if (rota === "admin/remover" && metodo === "POST") {
      delete todos[String(corpo.nome || "")];
      await put("colabs", todos);
      return json({ ok: true });
    }
    if (rota === "admin/senha" && metodo === "POST") {
      const nome = String(corpo.nome || "");
      if (!todos[nome]) return erro("Colaborador não encontrado.");
      let senha = String(corpo.senha || "").trim();
      if (senha && !/^\d{4,6}$/.test(senha)) return erro("A senha deve ter de 4 a 6 números.");
      if (!senha) senha = String(crypto.randomInt(1000, 10000));
      todos[nome].cred = novaCredencial(senha);
      await put("colabs", todos);
      await acertou(slug(nome));
      return json({ ok: true, senha });
    }
    if (rota === "admin/senha-admin" && metodo === "POST") {
      const nova = String(corpo.nova || "");
      if (nova.length < 6) return erro("Use pelo menos 6 caracteres.");
      await put("admin", novaCredencial(nova));
      return json({ ok: true });
    }
    return erro("Rota não encontrada.", 404);
  } catch (e) {
    console.error(e);
    return erro("Erro no servidor. Tente de novo.", 500);
  }
};

function somaDias(data, n) {
  const [y, m, d] = data.split("-").map(Number);
  const t = new Date(Date.UTC(y, m - 1, d + n));
  return t.toISOString().slice(0, 10);
}
