(() => {
  "use strict";
  var __webpack_exports__ = {};
  const buffToBase64 = buff => window.btoa(String.fromCharCode.apply(null, buff));
  const base64ToBuff = b64 => Uint8Array.from(window.atob(b64), (c => c.charCodeAt(0)));
  const enc = new TextEncoder;
  const dec = new TextDecoder;
  const byteLen = {
    salt: 16,
    iv: 12
  };
  const getKeyFromPassword = password => window.crypto.subtle.importKey("raw", enc.encode(password), {
    name: "PBKDF2"
  }, false, [ "deriveBits", "deriveKey" ]);
  const getKey = (keyFromPassword, salt) => window.crypto.subtle.deriveKey({
    name: "PBKDF2",
    salt,
    iterations: 1e5,
    hash: "SHA-256"
  }, keyFromPassword, {
    name: "AES-GCM",
    length: 256
  }, true, [ "encrypt", "decrypt" ]);
  const encrypt = async (secret, password) => {
    const keyFromPassword = await getKeyFromPassword(password);
    const salt = window.crypto.getRandomValues(new Uint8Array(byteLen.salt));
    const key = await getKey(keyFromPassword, salt);
    const iv = window.crypto.getRandomValues(new Uint8Array(byteLen.iv));
    const encoded = enc.encode(secret);
    const cipherText = await window.crypto.subtle.encrypt({
      name: "AES-GCM",
      iv
    }, key, encoded);
    const cipher = new Uint8Array(cipherText);
    const buffer = new Uint8Array(salt.byteLength + iv.byteLength + cipher.byteLength);
    buffer.set(salt, 0);
    buffer.set(iv, salt.byteLength);
    buffer.set(cipher, salt.byteLength + iv.byteLength);
    const encrypted = buffToBase64(buffer);
    return encrypted;
  };
  const decrypt = async (encrypted, password) => {
    const encryptedBuffer = base64ToBuff(encrypted);
    const salt = encryptedBuffer.slice(0, byteLen.salt);
    const iv = encryptedBuffer.slice(byteLen.salt, byteLen.salt + byteLen.iv);
    const cipherText = encryptedBuffer.slice(byteLen.salt + byteLen.iv);
    const keyFromPassword = await getKeyFromPassword(password);
    const key = await getKey(keyFromPassword, salt);
    try {
      const decryptedEncoded = await window.crypto.subtle.decrypt({
        name: "AES-GCM",
        iv
      }, key, cipherText);
      const decrypted = dec.decode(decryptedEncoded);
      return decrypted;
    } catch (e) {
      throw new Error(e);
    }
  };
  class ERP {
    onGetSecurityQues;
    isLoggedIn;
    logout;
    authRequest;
    getSecurityQues;
    constructor(roll) {
      let username = roll || "";
      let password = "";
      const securityQuestions = {};
      Object.defineProperties(this, {
        username: {
          get() {
            return username;
          }
        },
        password: {
          set(pass) {
            password = pass;
          }
        },
        securityQuestions: {
          set(ques) {
            if (ques instanceof Object) for (const q in ques) if (Object.keys(securityQuestions).includes(q)) securityQuestions[q] = ques[q];
          },
          get() {
            return securityQuestions;
          }
        },
        data: {
          get() {
            return {
              username,
              password,
              securityQuestions
            };
          }
        },
        load: {
          value(user) {
            const {username: id, password: pass, securityQuestions: ques} = user;
            if (id) username = id;
            if (pass) password = pass;
            if (ques) for (const q in ques) if (Object.prototype.hasOwnProperty.call(ques, q)) securityQuestions[q] = ques[q];
            void 0;
          }
        },
        getAllSecurityQues: {
          async value() {
            if (Object.keys(securityQuestions).length >= 3) return Object.keys(securityQuestions);
            let question;
            try {
              question = await this.getSecurityQues(username);
            } catch (error) {
              void 0;
              return false;
            }
            if (question === "FALSE") {
              void 0;
              return false;
            }
            if (Object.keys(securityQuestions).length < 3) {
              if (!Object.keys(securityQuestions).includes(question)) this.onGetSecurityQues(question);
              securityQuestions[question] = "";
              await this.getAllSecurityQues();
            }
            return Object.keys(securityQuestions);
          }
        },
        login: {
          async value(options) {
            let {requestedUrl} = options || {};
            const {sessionToken} = options || {};
            if (!requestedUrl) requestedUrl = "https://erp.iitkgp.ac.in/IIT_ERP3/";
            const isLoggedIn = await this.isLoggedIn(requestedUrl);
            void 0;
            if (isLoggedIn) return requestedUrl;
            let question;
            try {
              question = await this.getSecurityQues(username);
            } catch (error) {
              void 0;
              return false;
            }
            void 0;
            const answer = securityQuestions[question] || "";
            const redirectedUrl = await this.authRequest({
              username,
              password,
              answer,
              sessionToken,
              requestedUrl
            });
            return redirectedUrl;
          }
        }
      });
      this.onGetSecurityQues = function(question) {
        void 0;
      };
      this.logout = async function() {
        const url = "https://erp.iitkgp.ac.in/IIT_ERP3/logout.htm";
        const response = await processRequest(new Request(url));
        if (response.redirected) return response.url;
        return Promise.reject(new Error("Logout failed"));
      };
      this.isLoggedIn = async function(requestedUrl) {
        if (!requestedUrl) requestedUrl = "https://erp.iitkgp.ac.in/IIT_ERP3/";
        const res = await processRequest(new Request(requestedUrl));
        if (!res.redirected) return true;
        return false;
      };
      this.authRequest = async function(authCred) {
        const {username, password, answer, sessionToken, requestedUrl} = authCred;
        if (!username || !password || !answer) throw new Error("Username or Password or Answer is missing!");
        let body = `user_id=${username}&password=${password}&answer=${answer}`;
        if (sessionToken) body += `&sessionToken=${sessionToken}`;
        if (requestedUrl) body += `&requestedUrl=${requestedUrl}`; else body += "&requestedUrl=https://erp.iitkgp.ac.in/IIT_ERP3/";
        const url = "https://erp.iitkgp.ac.in/SSOAdministration/auth.htm";
        const method = "POST";
        void 0;
        const response = await processRequest(new Request(url, {
          method,
          body
        }));
        if (response.redirected) return response.url;
        return Promise.reject(new Error("Invalid credentials"));
      };
      this.getSecurityQues = async function(iitkgpLoginId) {
        if (!iitkgpLoginId) throw new Error("Please provide login id");
        const url = "https://erp.iitkgp.ac.in/SSOAdministration/getSecurityQues.htm";
        const method = "POST";
        const body = `user_id=${iitkgpLoginId}`;
        const response = await processRequest(new Request(url, {
          method,
          body
        }));
        return response ? response.text() : "FALSE";
      };
      const processRequest = async function(request) {
        let ts = Date.now();
        const {url, method} = request;
        const {pathname, search} = new URL(url);
        const response = await nativeFetch(request);
        ts -= Date.now();
        void 0;
        if (response.ok && response.status === 200) return response;
        return Promise.reject(new Error("Api returned status: " + response.status));
      };
      const nativeFetch = function(request) {
        if (request.method === "POST") request.headers.set("Content-type", "application/x-www-form-urlencoded");
        return fetch(request);
      };
    }
  }
  const erp = ERP;
  const displayMessageOnPopup = (message, type = "info", actions = false, onClickYes = (() => {}), onclickCancel = (() => {})) => {
    const log = document.getElementById("log");
    const logIcon = document.getElementById("logIcon");
    const logText = document.getElementById("logText");
    const status = document.getElementById("status");
    const statusIcon = document.getElementById("statusIcon");
    const statusText = document.getElementById("statusText");
    let iconId;
    log.className = type;
    status.style.backgroundColor = "yellow";
    switch (type) {
     case "warning":
      iconId = "warning";
      break;

     case "error":
      iconId = "cross";
      break;

     case "success":
      iconId = "check";
      status.style.backgroundColor = "lightgreen";
      break;

     default:
      iconId = "info";
      break;
    }
    logText.textContent = message;
    logIcon.setAttribute("href", chrome.runtime.getURL(`/assets/sprite.svg#${iconId || "info"}`));
    statusText.textContent = message;
    statusIcon.setAttribute("href", chrome.runtime.getURL(`/assets/sprite.svg#${iconId || "info"}`));
    if (actions) {
      document.querySelectorAll(".action").forEach((el => el.remove()));
      const actionBtnYes = document.createElement("div");
      actionBtnYes.className = "action";
      actionBtnYes.textContent = "Yes";
      const actionBtnCancel = document.createElement("div");
      actionBtnCancel.className = "action";
      actionBtnCancel.textContent = "Cancel";
      log.appendChild(actionBtnYes);
      log.appendChild(actionBtnCancel);
      actionBtnYes.onclick = () => {
        log.removeChild(actionBtnYes);
        log.removeChild(actionBtnCancel);
        onClickYes();
      };
      actionBtnCancel.onclick = () => {
        log.removeChild(actionBtnYes);
        log.removeChild(actionBtnCancel);
        onclickCancel();
      };
    }
  };
  const utils_displayMessageOnPopup = displayMessageOnPopup;
  chrome.storage.local.get([ "theme", "bg", "landingPage", "useAltPINDialog" ], (result => {
    const useAltPINDialogInput = document.getElementById("useAltPINDialog");
    useAltPINDialogInput.checked = result.useAltPINDialog || false;
    useAltPINDialogInput.onchange = ev => {
      chrome.storage.local.set({
        useAltPINDialog: ev.target.checked
      });
    };
    const landingPageSelect = document.getElementById("landing_page");
    const themeSelect = document.getElementById("theme_select");
    const themeBg = document.getElementById("theme-bg");
    let isDark = false;
    let isBgEnabled = false;
    if (result.theme === "dark" || !("theme" in result) && window.matchMedia("(prefers-color-scheme: dark)").matches) {
      isDark = true;
      document.documentElement.classList.add("dark");
      themeSelect.value = "dark";
    } else {
      document.documentElement.classList.remove("dark");
      themeSelect.value = "light";
    }
    if (result.bg === "yes") {
      isBgEnabled = true;
      if (isDark) document.body.classList.toggle("bg-theme-dark"); else document.body.classList.toggle("bg-theme");
      themeBg.checked = true;
    } else themeBg.checked = false;
    themeBg.onchange = ev => {
      if (ev.target.checked) {
        isBgEnabled = true;
        if (isDark) document.body.classList.toggle("bg-theme-dark"); else document.body.classList.toggle("bg-theme");
      } else {
        isBgEnabled = false;
        document.body.classList.remove("bg-theme");
        document.body.classList.remove("bg-theme-dark");
      }
      chrome.storage.local.set({
        bg: ev.target.checked ? "yes" : "no"
      });
    };
    themeSelect.onchange = ev => {
      isDark = ev.target.value === "dark";
      if (isBgEnabled) {
        document.body.classList.remove("bg-theme");
        document.body.classList.remove("bg-theme-dark");
        if (isDark) document.body.classList.toggle("bg-theme-dark"); else document.body.classList.toggle("bg-theme");
      }
      document.documentElement.classList.toggle("dark");
      chrome.storage.local.set({
        theme: ev.target.value
      });
    };
    if (result.landingPage) landingPageSelect.value = result.landingPage;
    landingPageSelect.onchange = ev => {
      chrome.storage.local.set({
        landingPage: ev.target.value
      });
    };
  }));
  window.addEventListener("DOMContentLoaded", (() => {
    chrome.storage.local.get({
      authCredentials: {
        requirePin: false,
        autoLogin: true,
        username: "",
        password: "",
        q1: "",
        q2: "",
        q3: "",
        a1: "",
        a2: "",
        a3: ""
      }
    }, (result => {
      const authCredentials = result.authCredentials;
      void 0;
      const form = document.getElementById("form_add_user");
      const formResetBtn = document.getElementById("reset_form");
      const formSubmitBtn = document.getElementById("submit_form");
      const username = document.getElementById("username");
      const usernameSubmitBtn = document.getElementById("username_submit_button");
      const password = document.getElementById("password");
      const a1 = document.getElementById("question_one");
      const a2 = document.getElementById("question_two");
      const a3 = document.getElementById("question_three");
      const pin = document.getElementById("pin");
      const questions = document.querySelectorAll("input[name='question']");
      const formToggleBtns = document.querySelectorAll(".left-button,.right-button");
      const loader = document.getElementById("loader");
      const container = document.querySelector(".box-container");
      const autoLoginToggleBtn = document.getElementById("autoLogin");
      username.value = authCredentials.username || "";
      password.value = authCredentials.password || "";
      a1.value = authCredentials.a1 || "";
      a2.value = authCredentials.a2 || "";
      a3.value = authCredentials.a3 || "";
      a1.placeholder = authCredentials.q1 || "Your erp question 1";
      a2.placeholder = authCredentials.q2 || "Your erp question 2";
      a3.placeholder = authCredentials.q3 || "Your erp question 3";
      autoLoginToggleBtn.checked = authCredentials.autoLogin;
      if (authCredentials.username === "") {
        utils_displayMessageOnPopup("Enter Roll Number");
        username.removeAttribute("disabled");
        usernameSubmitBtn.removeAttribute("disabled");
      } else {
        utils_displayMessageOnPopup(`You are all set! ${authCredentials.username}`, "success");
        pin.style.display = "none";
        const smallText = document.createElement("b");
        smallText.setAttribute("style", "margin-left: 50px");
        if (authCredentials.requirePin) smallText.innerText = "PIN was set !"; else smallText.innerText = "PIN was NOT set !";
        pin.after(smallText);
      }
      const emptyFieldExists = authCredentials.username === "" || authCredentials.password === "" || authCredentials.a1 === "" || authCredentials.q1 === "Your erp question 1" || authCredentials.a2 === "" || authCredentials.q2 === "Your erp question 2" || authCredentials.a3 === "" || authCredentials.q3 === "Your erp question 2";
      if (emptyFieldExists) container.classList.toggle("right-open");
      formToggleBtns.forEach((button => button.addEventListener("click", (() => {
        container.classList.toggle("right-open");
      }))));
      autoLoginToggleBtn.addEventListener("change", (e => {
        const target = e.target;
        void 0;
        void 0;
        authCredentials[target.id] = target.checked;
        chrome.storage.local.set({
          authCredentials
        });
      }));
      form.addEventListener("submit", (async e => {
        e.preventDefault();
        loader.style.display = "flex";
        setTimeout((() => {
          loader.style.display = "none";
        }), 500);
        if (pin.value) {
          pin.style.display = "none";
          const smallText = document.createElement("small");
          smallText.setAttribute("style", "margin-left: 50px");
          smallText.innerText = "PIN is set!";
          pin.after(smallText);
          const [ans1, ans2, ans3, pass] = await Promise.all([ encrypt(a1.value, pin.value), encrypt(a2.value, pin.value), encrypt(a3.value, pin.value), encrypt(password.value, pin.value) ]);
          const encryptedCred = {
            autoLogin: authCredentials.autoLogin,
            username: username.value,
            q1: a1.placeholder,
            q2: a2.placeholder,
            q3: a3.placeholder,
            requirePin: true,
            password: pass,
            a1: ans1,
            a2: ans2,
            a3: ans3
          };
          chrome.storage.local.set({
            authCredentials: encryptedCred
          }, (() => location.reload()));
        } else {
          const credentials = {
            autoLogin: authCredentials.autoLogin,
            username: username.value,
            q1: a1.placeholder,
            q2: a2.placeholder,
            q3: a3.placeholder,
            requirePin: false,
            password: password.value,
            a1: a1.value,
            a2: a2.value,
            a3: a3.value
          };
          chrome.storage.local.set({
            authCredentials: credentials
          }, (() => location.reload()));
        }
      }));
      formResetBtn.addEventListener("click", (e => {
        e.preventDefault();
        utils_displayMessageOnPopup("Are you sure!", "warning", true, (() => {
          void 0;
          document.forms[0].reset();
          chrome.storage.local.remove([ "authCredentials" ], (() => {
            location.reload();
          }));
        }), (() => {
          utils_displayMessageOnPopup("Cancelled.");
        }));
      }));
      username.addEventListener("keyup", (e => {
        e.preventDefault();
        if (username.value.length !== 9) {
          if (username.value.length === 8 || username.value.length === 10) {
            questions.forEach(((q, i) => {
              q.placeholder = `Your erp question ${i + 1}`;
              q.value = "";
              q.disabled = true;
            }));
            password.value = "";
            pin.value = "";
            password.disabled = true;
            pin.disabled = true;
          }
          return;
        }
      }));
      usernameSubmitBtn.addEventListener("click", (async e => {
        e.preventDefault();
        utils_displayMessageOnPopup("Getting questions, wait...");
        const erpUser = new erp(username.value);
        erpUser.getAllSecurityQues().then((res => {
          if (res === false) utils_displayMessageOnPopup("Invalid RollNo!", "error"); else {
            utils_displayMessageOnPopup("Questions fetched!", "success");
            password.removeAttribute("disabled");
            pin.removeAttribute("disabled");
            formSubmitBtn.removeAttribute("disabled");
          }
        }));
        let idx = 0;
        erpUser.onGetSecurityQues = q => {
          questions[idx].removeAttribute("disabled");
          questions[idx].placeholder = q;
          idx++;
        };
      }));
      setTimeout((() => {
        loader.style.display = "none";
      }), 500);
    }));
  }));
})();