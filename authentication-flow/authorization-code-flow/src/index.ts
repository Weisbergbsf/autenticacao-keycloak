import crypto from "crypto";
import express, { NextFunction, Request, Response } from "express";
import session from "express-session";
import jwt from "jsonwebtoken";

const app = express();

const memoryStore = new session.MemoryStore();

app.use(
    session({
        secret: "my-secret",
        resave: false,
        saveUninitialized: false,
        store: memoryStore
    })
);

const middlewareIsAuth = (req: Request, res: Response, next: NextFunction ) => {
    //@ts-expect-error - type mismatch
    if(!req.session.user) {
        return res.redirect('/login');
    }
    next();
}
// Nonce - Number used once

app.get('/login', (req, res) => {
    const nonce = crypto.randomBytes(16).toString("base64");
    const state = crypto.randomBytes(16).toString("base64");

    //@ts-expect-error
    req?.session?.nonce = nonce;
    //@ts-expect-error
    req?.session?.state = state;
    //@ts-ignore
    req?.session?.save();

    const loginParams = new URLSearchParams({
        client_id: 'fullcycle-client',
        redirect_uri: 'http://localhost:3000/callback',
        response_type: 'code',
        scope: 'openid',
        nonce,
        state,
    });
    const url = `http://localhost:8080/realms/fullcycle-realm/protocol/openid-connect/auth?${loginParams.toString()}`;

    res.redirect(url)
})

app.get('/callback', async (req, res) => {
    //@ts-expect-error
    if(req.query.state !== req.session.state) {
        // poderia redirecionar para o login em vez de mostrar o error
        return res.status(401).json({ message: "Unauthenticated" });
    }

    const bodyParams = new URLSearchParams({
        client_id: 'fullcycle-client',
        grant_type: 'authorization_code',
        code: req.query.code as string,
        redirect_uri: 'http://localhost:3000/callback',
    });

    const url = `http://host.docker.internal:8080/realms/fullcycle-realm/protocol/openid-connect/token`;

    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: bodyParams.toString()
    });

    const result = await response.json();

    const payloadAccessToken = jwt.decode(result.access_token) as any;
    const payloadRefreshToken = jwt.decode(result.refresh_token) as any;
    const payloadIdToken = jwt.decode(result.id_token) as any;

    if(
        //@ts-expect-error
        payloadAccessToken?.nonce !== req.session.nonce || 
        //@ts-expect-error
        payloadRefreshToken?.nonce !== req.session.nonce || 
        //@ts-expect-error
        payloadIdToken?.nonce !== req.session.nonce
        ) {
           return res.status(401).json({ message: "Unauthenticated" });
        }
    
    //@ts-expect-error
    req.session.user = payloadAccessToken;
    //@ts-expect-error
    req.session.access_token = result.access_token;
    //@ts-expect-error
    req.session.id_token = result.id_token;
    res.json(result)
})

app.listen(3000, () => {
    console.log('Listening on port 3000');
})