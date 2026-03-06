class HttpError extends Error {
    constructor(message, statusCode, statusText) {
        super(message);
        this.statusCode = statusCode;
        this.statusText = statusText;
    }
}

function decodeBase64(base64) {
    const text = atob(base64);
    const length = text.length;
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        bytes[i] = text.charCodeAt(i);
    }
    const decoder = new TextDecoder(); // default is utf-8
    return decoder.decode(bytes);
}

function decodeJwt(rawToken) {
    const base64 = rawToken.split('.')?.[1]?.replace('-', '+')?.replace('_', '/');
    return JSON.parse(decodeBase64(base64));
}

function rememberRequestForm() {
    const clientId = document.getElementById("client_id").value;
    const responseType = document.getElementById("response_type").value;
    const scope = document.getElementById("scope").value;
    const codeVerifier = document.getElementById("code_verifier").value;
    sessionStorage.setItem("client_id", clientId);
    sessionStorage.setItem("response_type", responseType);
    sessionStorage.setItem("scope", scope);
    if (responseType === "code") {
        sessionStorage.setItem('code_verifier', codeVerifier);
    }
}

function updateFields(responseType) {
    if (responseType === "code") {
        document.querySelectorAll("#code_challenge, #code_challenge_method, #nonce, #scope").forEach(input => {
            input.disabled = false;
        });
        document.querySelectorAll("#client_secret, #username, #password, #txa_token").forEach(input => {
            input.disabled = true;
        });
    } else if (responseType === "token") {
        document.querySelectorAll("#code_challenge, #code_challenge_method, #nonce, #client_secret, #username, #password, #txa_token").forEach(input => {
            input.disabled = true;
        });
        document.querySelectorAll("#scope").forEach(input => {
            input.disabled = false;
        });
    } else if (responseType === "client_credentials") {
        document.querySelectorAll("#code_challenge, #code_challenge_method, #nonce, #username, #password, #txa_token").forEach(input => {
            input.disabled = true;
        });
        document.querySelectorAll("#scope, #client_secret").forEach(input => {
            input.disabled = false;
        });
    } else if (responseType === "password") {
        document.querySelectorAll("#code_challenge, #code_challenge_method, #nonce, #txa_token").forEach(input => {
            input.disabled = true;
        });
        document.querySelectorAll("#username, #password, #scope, #client_secret").forEach(input => {
            input.disabled = false;
        });
    } else if (responseType === "refresh_token") {
        document.querySelectorAll("#code_challenge, #code_challenge_method, #scope, #nonce, #username, #password").forEach(input => {
            input.disabled = true;
        });
        document.querySelectorAll("#client_secret, #txa_token").forEach(input => {
            input.disabled = false;
        });
    }
}

function onResponseTypeChange(event) {
    updateFields(event.target.value);
}

function getToken(params) {
    const postParams = new URLSearchParams(params);
    fetch("token", {method: "POST", body: postParams})
        .then(async resp => {
            if (!resp.ok) {
                throw new HttpError(await resp.text(), resp.status, resp.statusText);
            }
            return resp.json();
        })
        .then(data => {
            if (data.access_token) {
                document.getElementById("access_token_output").textContent = data.access_token;
                document.getElementById("access_token_json").textContent = JSON.stringify(decodeJwt(data.access_token), null, 2);
                document.getElementById("access_token_panel").style.display = 'block';
            }
            if (data.refresh_token) {
                document.getElementById("refresh_token_output").textContent = data.refresh_token;
                document.getElementById("refresh_token_panel").style.display = 'block';
            } else {
                document.getElementById("refresh_token_output").textContent = '';
                document.getElementById("refresh_token_panel").style.display = 'none';
            }
            if (data.id_token) {
                document.getElementById("id_token_output").textContent = data.id_token;
                document.getElementById("id_token_json").textContent = JSON.stringify(decodeJwt(data.id_token), null, 2);
                document.getElementById("id_token_panel").style.display = 'block';
            } else {
                document.getElementById("id_token_output").textContent = '';
                document.getElementById("id_token_json").textContent = '';
                document.getElementById("id_token_panel").style.display = 'none';
            }
        })
        .catch(error => {
            console.error(error);
            document.getElementById("access_token_output").textContent = `${error.statusCode} ${error.statusText}`;
            document.getElementById("access_token_json").textContent = error.message;
            document.getElementById("access_token_panel").style.display = 'block';
            document.getElementById("refresh_token_panel").style.display = 'none';
            document.getElementById("id_token_panel").style.display = 'none';
        });
}

function onRequestFormSubmit(event) {
    const checkedScopes = document.querySelectorAll('input[id^="scope_"]:checked');
    document.getElementById("scope").value = Array.from(checkedScopes).map(input => input.value).join(' ');

    const responseType = document.getElementById("response_type").value;
    if (responseType === 'client_credentials') {
        event.preventDefault();
        getToken({
            "grant_type": "client_credentials",
            "client_id": document.getElementById("client_id").value,
            "client_secret": document.getElementById("client_secret").value,
            "scope": document.getElementById("scope").value
        });
    } else if (responseType === 'password') {
        event.preventDefault();
        getToken({
            "grant_type": "password",
            "client_id": document.getElementById("client_id").value,
            "client_secret": document.getElementById("client_secret").value,
            "username": document.getElementById("username").value,
            "password": document.getElementById("password").value,
            "scope": document.getElementById("scope").value
        });
    } else if (responseType === 'refresh_token') {
        event.preventDefault();
        getToken({
            "grant_type": "refresh_token",
            "client_id": document.getElementById("client_id").value,
            "client_secret": document.getElementById("client_secret").value,
            "refresh_token": document.getElementById("txa_token").value
        });
    }

    rememberRequestForm();
}

document.getElementById('response_type').addEventListener("change", onResponseTypeChange);
document.getElementById('request_form').addEventListener("submit", onRequestFormSubmit);
document.addEventListener('DOMContentLoaded', () => {
    if (document.readyState === 'loading') {
        return;
    }

    const rememberedResponseType = sessionStorage.getItem("response_type");
    if (rememberedResponseType) {
        document.getElementById("response_type").value = rememberedResponseType;
        updateFields(rememberedResponseType);
    }

    const rememberedClientId = sessionStorage.getItem("client_id");
    if (rememberedClientId) {
        document.getElementById("client_id").value = rememberedClientId;
    }

    const rememberedScope = sessionStorage.getItem("scope");
    if (rememberedScope) {
        const rememberedScopes = rememberedScope.split(/\s+/g);
        document.getElementById("scope").value = rememberedScope;
        document.querySelectorAll('input[id^="scope_"]').forEach(input => {
            input.checked = rememberedScopes.includes(input.value);
        });
    }

    let urlParams = new URLSearchParams();
    const hash = window.location.hash.substring(1);
    if (hash) {
        urlParams = new URLSearchParams(hash);
    } else if (window.location.search) {
        urlParams = new URLSearchParams(window.location.search);
    }
    if (urlParams.has("access_token") === true) {
        const accessToken = urlParams.get("access_token");
        document.getElementById("access_token_output").textContent = accessToken;
        document.getElementById("access_token_json").textContent = JSON.stringify(decodeJwt(accessToken), null, 2);
        document.getElementById("access_token_panel").style.display = 'block';
    } else if (urlParams.has("code") === true) {
        getToken({
            "grant_type": "authorization_code",
            "code": urlParams.get("code"),
            "client_id": sessionStorage.getItem('client_id'),
            "code_verifier": sessionStorage.getItem('code_verifier')
        });
    }
});
