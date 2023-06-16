import { useContext, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { AuthContext } from "./AuthProvider";
import { ACCESS_TOKEN, ID_TOKEN, STATE } from "./utils";

export function Callback() {
    const { hash } = useLocation();
    const { login, auth } = useContext(AuthContext);
    const navigate = useNavigate();

    console.log(hash)

    useEffect(() => {
        if(auth) {
            navigate("/login")
            return;
        }
        const searchParams = new URLSearchParams(hash.replace("#", ""));
        const accessToken = searchParams.get(ACCESS_TOKEN);
        const idToken = searchParams.get(ID_TOKEN);
        const state = searchParams.get(STATE);

        if(!accessToken || !idToken || !state) {
            navigate("/login")
            return;
        }

        login(accessToken, idToken, state);
 
    },[hash, login, auth, navigate])

    return <div>Loading...</div>;
}