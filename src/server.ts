import express from "express";
import { join } from "node:path";
import { createHmac, timingSafeEqual } from "node:crypto";
import type { Request } from "express";

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(express.static(join(process.cwd(), "public")));

// Provjera rada poslužitelja
app.get("/api/health", (_req, res) => {
    res.json({ status: "ok" });
});

// Zamjena posebnih HTML znakova
function escapeHtml(text: string): string {
    const replacements: Record<string, string> = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    };

    return text.replace(
        /[&<>"']/g,
        (character) => replacements[character]
    );
}

// Demonstracija reflektiranog XSS napada
app.get("/xss", (req, res) => {
    const message =
        typeof req.query.message === "string"
            ? req.query.message.slice(0, 2000)
            : "";

    const vulnerable = req.query.vulnerable === "on";

    // Izolacija demonstracije od ostatka aplikacije
    res.setHeader(
        "Content-Security-Policy",
        "sandbox allow-scripts allow-modals; " +
        "default-src 'none'; " +
        "script-src 'unsafe-inline'; " +
        "style-src 'unsafe-inline'; " +
        "base-uri 'none'; " +
        "form-action 'none'"
    );

    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "no-store");

    // Ranjivo: izravno ugrađivanje korisničkog unosa
    // Sigurno: HTML escaping prije ugrađivanja
    const output = vulnerable
        ? message
        : escapeHtml(message);

    res.type("html").send(`
        <!DOCTYPE html>
        <html lang="hr">
        <head>
            <meta charset="UTF-8">
            <title>XSS rezultat</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    padding: 10px;
                    overflow-wrap: anywhere;
                }

                #xss-output {
                    padding: 10px;
                    background: #f1f5f9;
                    border-radius: 5px;
                }

                #xss-status {
                    margin-top: 12px;
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
            <p>
                <strong>Način rada:</strong>
                ${vulnerable
                    ? "Ranjivost uključena"
                    : "Ranjivost isključena"}
            </p>

            <div id="xss-output">${output}</div>

            <p id="xss-status">
                JavaScript nije izvršen.
            </p>
        </body>
        </html>
    `);
});


/* =====================================
   BROKEN ACCESS CONTROL - IDOR
===================================== */

// Testni korisnici
const users = [
    { id: 1, username: "ana", password: "ana123" },
    { id: 2, username: "marko", password: "marko123" }
];

// Privatni zapisi
const records = [
    {
        id: 1001,
        ownerId: 1,
        title: "Anin privatni zapis",
        content: "Anine privatne bilješke."
    },
    {
        id: 1002,
        ownerId: 2,
        title: "Markov privatni zapis",
        content: "Markovi povjerljivi projektni podaci."
    }
];

// Potpisivanje sjednica
const SESSION_COOKIE = "demo_session";
const SESSION_DURATION = 2 * 60 * 60 * 1000;

function getSessionSecret(): string {
    const secret = process.env.SESSION_SECRET;

    if (secret) {
        return secret;
    }

    if (process.env.NODE_ENV === "production") {
        throw new Error(
            "SESSION_SECRET mora biti postavljen u produkciji."
        );
    }

    return "local-development-secret";
}

const SESSION_SECRET: string = getSessionSecret();


function sign(value: string): string {
    return createHmac("sha256", SESSION_SECRET)
        .update(value)
        .digest("base64url");
}

function createSession(userId: number): string {
    const payload = Buffer.from(
        JSON.stringify({
            userId,
            expiresAt: Date.now() + SESSION_DURATION
        })
    ).toString("base64url");

    return `${payload}.${sign(payload)}`;
}

// Dohvaćanje autentificiranog korisnika
function getCurrentUser(req: Request) {
    const cookie = req.headers.cookie
        ?.split(";")
        .map(part => part.trim())
        .find(part =>
            part.startsWith(`${SESSION_COOKIE}=`)
        );

    if (!cookie) return null;

    const token = cookie.slice(SESSION_COOKIE.length + 1);
    const parts = token.split(".");

    if (parts.length !== 2) return null;

    const [payload, signature] = parts;
    const expected = sign(payload);

    const actualBuffer = Buffer.from(signature);
    const expectedBuffer = Buffer.from(expected);

    if (
        actualBuffer.length !== expectedBuffer.length ||
        !timingSafeEqual(actualBuffer, expectedBuffer)
    ) {
        return null;
    }

    try {
        const data = JSON.parse(
            Buffer.from(payload, "base64url").toString("utf8")
        );

        if (
            !Number.isSafeInteger(data.userId) ||
            !Number.isFinite(data.expiresAt) ||
            data.expiresAt <= Date.now()
        ) {
            return null;
        }

        return users.find(
            user => user.id === data.userId
        ) ?? null;
    } catch {
        return null;
    }
}

// Prijava korisnika
app.post("/login", (req, res) => {
    const { username, password } = req.body ?? {};

    const user = users.find(
        user =>
            user.username === username &&
            user.password === password
    );

    if (!user) {
        return res.status(401).json({
            message: "Neispravno korisničko ime ili lozinka."
        });
    }

    res.cookie(
        SESSION_COOKIE,
        createSession(user.id),
        {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
            maxAge: SESSION_DURATION,
            path: "/"
        }
    );

    res.json({
        message: "Prijava uspješna.",
        username: user.username
    });
});

// Provjera trenutne sjednice
app.get("/me", (req, res) => {
    res.setHeader("Cache-Control", "no-store");

    const user = getCurrentUser(req);

    res.json({
        authenticated: user !== null,
        username: user?.username ?? null
    });
});

// Odjava korisnika
app.post("/logout", (_req, res) => {
    res.clearCookie(SESSION_COOKIE, {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        path: "/"
    });

    res.json({
        message: "Odjava uspješna."
    });
});

// Dohvaćanje privatnog zapisa - IDOR
app.get("/records", (req, res) => {
    res.setHeader("Cache-Control", "no-store");

    const user = getCurrentUser(req);

    // Autentifikacija je obvezna u oba načina rada
    if (!user) {
        return res.status(401).json({
            message: "Korisnik nije prijavljen."
        });
    }

    const id = req.query.id;

    if (
        typeof id !== "string" ||
        !/^\d+$/.test(id) ||
        !Number.isSafeInteger(Number(id))
    ) {
        return res.status(400).json({
            message: "Neispravan identifikator zapisa."
        });
    }

    const record = records.find(
        record => record.id === Number(id)
    );

    if (!record) {
        return res.status(404).json({
            message: "Zapis ne postoji."
        });
    }

    const vulnerable = req.query.vulnerable === "on";

    // Zaštićeni način: provjera vlasništva
    if (!vulnerable && record.ownerId !== user.id) {
        return res.status(403).json({
            message: "Zabranjen pristup tuđem zapisu.",
            check: "Provjera vlasništva: odbijeno"
        });
    }

    // Ranjivi način: provjera vlasništva se preskače
    const owner = users.find(
        user => user.id === record.ownerId
    );

    res.json({
        message: "Pristup zapisu uspješan.",
        check: vulnerable
            ? "Provjera vlasništva: preskočena"
            : "Provjera vlasništva: uspješna",
        record: {
            id: record.id,
            title: record.title,
            content: record.content,
            owner: owner?.username
        }
    });
});


app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
});
