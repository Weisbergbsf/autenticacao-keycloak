import { decodeJwt } from "jose";
import Cookies from "js-cookie";

// http://localhost:8080/realms/fullcycle-realm/.well-known/openid-configuration
// http://localhost:8080/realms/fullcycle-realm/protocol/openid-connect/certs

export const ACCESS_TOKEN = "access_token";
export const ID_TOKEN = "access_token";
export const NONCE = "nonce";
export const STATE = "state";

export function makeLoginUrl(){
    const nonce = Math.random().toString(36);
    const state = Math.random().toString(36);

    // lembrar de armazenar com cookie sewguro (https)
    Cookies.set(NONCE, nonce);
    Cookies.set("state", state);

    const loginUrlParams = new URLSearchParams({
        client_id: "fullcycle-client",
        redirect_uri: "http://localhost:3000/callback",
        response_type: "token id_token",
        // scope: "openid",
        nonce: nonce,
        state: state,
    });

    return `http://localhost:8080/realms/fullcycle-realm/protocol/openid-connect/auth?${loginUrlParams.toString()}`;
}

export function login(accessToken: string, idToken: string, state: string) {
    const stateCookie = Cookies.get(STATE);
    
    if(stateCookie !== state) {
        throw new Error("Invalid state");
    }

    let decodedAccessToken = null;
    let decodedIdToken = null;

    try {
        decodedAccessToken = decodeJwt(accessToken);
        decodedIdToken = decodeJwt(idToken);
    } catch (error) {
        throw new Error("Invalid token");
    }

    if(decodedAccessToken.nonce !== Cookies.get(NONCE)) {
        throw new Error("Invalid nonce");
    }

    if(decodedIdToken.nonce !== Cookies.get(NONCE)) {
        throw new Error("Invalid nonce");
    }

    Cookies.set(ACCESS_TOKEN, accessToken);
    Cookies.set(ID_TOKEN, idToken);

    return decodedAccessToken;
}

export function getAuth(){
    const token = Cookies.get(ACCESS_TOKEN);

    if(!token) {
        return null;
    }

    try {
        return decodeJwt(token);
    } catch (error) {
        console.log(error);
        return null;
    }
}

export function makeLogoutUrl(){
    if(!Cookies.get(ID_TOKEN)) {
        return;
    }

    const logoutParams = new URLSearchParams({
        id_token_hint: Cookies.get(ID_TOKEN) as string,
        post_logout_redirect_uri: 'http://localhost:3000/login',
    });

    Cookies.remove(ACCESS_TOKEN);
    Cookies.remove(ID_TOKEN);
    Cookies.remove(NONCE);
    Cookies.remove(STATE);
    
    return `http://localhost:8080/realms/fullcycle-realm/protocol/openid-connect/logout?${logoutParams.toString()}`;
    
}