import { JWTPayload } from "jose";
import { PropsWithChildren, createContext, useCallback, useState } from "react";
import * as utils from "./utils";

type AuthProviderProps = {
    auth: JWTPayload | null;
    makeLoginUrl: () => string;
    makeLogoutUrl: () => string | undefined;
    login: (accessToken: string, idToken: string, state: string) => JWTPayload;
}

const initContextData: AuthProviderProps = {
    auth: null,
    makeLoginUrl: utils.makeLoginUrl,
    // @ts-expect-error - this is a mock function
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    makeLogoutUrl: () => { },
    // @ts-expect-error - this is a mock function
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    login: () => { },
};

export const AuthContext = createContext(initContextData);

export const AuthProvider = (props: PropsWithChildren) => {
    const makeLogin = useCallback((accessToken: string, idToken: string, state: string) => {
        const authData = utils.login(accessToken, idToken, state);
        setData((oldData) => ({
            auth: authData,
            makeLoginUrl: oldData.makeLoginUrl,
            makeLogoutUrl: oldData.makeLogoutUrl,
            login: oldData.login,
        }));

        return authData;
    }, []);

    const [data, setData] = useState({
        auth: utils.getAuth(),
        makeLoginUrl: utils.makeLoginUrl,
        makeLogoutUrl: utils.makeLogoutUrl,
        login: makeLogin,
    });

    return <AuthContext.Provider value={data}>{props.children}</AuthContext.Provider>
}