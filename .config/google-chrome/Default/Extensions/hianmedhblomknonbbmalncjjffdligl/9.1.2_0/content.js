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
  const MESSAGE_ELEMENT_ID = "erp_auto_login_message";
  const displayMessageOnErpLoginPage = (message, color = "#45a1ff") => {
    if (document.getElementById(MESSAGE_ELEMENT_ID)) document.getElementById(MESSAGE_ELEMENT_ID).remove();
    const msg = document.createElement("div");
    msg.setAttribute("id", MESSAGE_ELEMENT_ID);
    msg.setAttribute(`style`, `background-image: linear-gradient(to right, ${color}, rgb(237,78,80));color: #ffffff;font-weight:500; width:100%; height:35px; text-align: center;display:flex; justify-content: center; align-items: center;flex-direction:row`);
    msg.textContent = message;
    document.body.prepend(msg);
  };
  const utils_displayMessageOnErpLoginPage = displayMessageOnErpLoginPage;
  const pinDialog = document.createElement("dialog");
  pinDialog.id = "pinDialog";
  pinDialog.open = false;
  pinDialog.innerHTML = `\n  <div class="prompt">\n    Enter your 4 digit PIN\n  </div>\n  <form class="digit-group" data-group-name="digits" data-autosubmit="false" autocomplete="off">\n\t<input type="password" id="digit-1" name="digit-1" data-next="digit-2" />\n    <input type="password" id="digit-2" name="digit-2" data-next="digit-3" data-previous="digit-1" />\n    <input type="password" id="digit-3" name="digit-3" data-next="digit-4" data-previous="digit-2" />\n    <input type="password" id="digit-4" name="digit-4" data-previous="digit-3" />\n  </form>\n\t<button id="pinDialogCloseBtn">Close</button>\n`;
  const style = document.createElement("style");
  style.innerHTML = `\nbody {\n  overflow: hidden;\n}\ndialog {\n    z-index: 2147483646 !important;\n    position: fixed;\n    // top: 50%;\n    left: 50%;\n    transform: translate(-50%, 0%);\n    width: 340px;\n    // height: 200px;\n    border: none;\n    border-radius: 0 0 3px 3px;\n    box-shadow: 0 3px 10px rgba(0, 0, 0, 0.5);\n    padding: 10px;\n    padding-left: 35px;\n    margin: 0;\n    \n    background-color: #fff;\n    // background-color: #0f0f1a;\n    display: flex;\n    align-items: center;\n    justify-content: center;\n    flex-direction: column;\n\n    background-image: url("${chrome.runtime.getURL("assets/images/ext_icon.png")}");\n    background-repeat: no-repeat;\n    background-position: 25px center;\n    background-size: 50px;\n  }\n  \n  dialog::backdrop {\n    background-color: rgba(0 0 0 / 0.5);\n    // backdrop-filter: blur(3px);\n  }\n\n  \n.digit-group input {\n  width: 30px;\n  height: 50px;\n  // background-color: #18182a;\n  background-color: #fff;\n  border: 2px solid gray;\n  border-radius: 5px;\n  border-opacity: 0.5;\n  line-height: 50px;\n  text-align: center;\n  font-size: 24px;\n  font-family: "Raleway", sans-serif;\n  font-weight: 200;\n  // color: white;\n  color: black;\n  margin: 0 2px;\n}\n\n.prompt {\n  margin-bottom: 20px;\n  font-size: 16px;\n  // color: white;\n  color: black;\n}\n#pinDialogCloseBtn {\n  margin-top: 20px;\n  border-radius: 5px;\n  border: none;\n  // color: white;\n  color: black;\n  padding: 5px 10px;\n}\n`;
  async function getPinFromDialog() {
    let pin = "";
    document.head.appendChild(style);
    document.body.appendChild(pinDialog);
    pinDialog.showModal();
    const pinDialogCloseBtn = document.getElementById("pinDialogCloseBtn");
    pinDialogCloseBtn.addEventListener("click", (() => {
      pinDialog.close();
    }));
    const digitGroups = document.querySelectorAll(".digit-group");
    digitGroups.forEach((digitGroup => {
      const inputs = digitGroup.querySelectorAll("input");
      inputs.forEach((input => {
        input.setAttribute("maxlength", "1");
        input.addEventListener("keyup", (e => {
          const parent = input.parentElement;
          if (e.keyCode === 8 || e.keyCode === 37) {
            const prev = parent.querySelector(`input#${input.dataset.previous}`);
            if (prev) prev.select();
          } else if (e.keyCode >= 48 && e.keyCode <= 57 || e.keyCode >= 65 && e.keyCode <= 90 || e.keyCode >= 96 && e.keyCode <= 105 || e.keyCode === 39) {
            const next = parent.querySelector(`input#${input.dataset.next}`);
            if (next) next.select(); else if (parent.dataset.autosubmit) {
              void 0;
              pin = inputs[0].value + inputs[1].value + inputs[2].value + inputs[3].value;
              pinDialog.close();
            }
          }
        }));
      }));
    }));
    await new Promise((resolve => {
      pinDialog.addEventListener("close", resolve);
    }));
    pinDialog.remove();
    style.remove();
    return new Promise(((resolve, reject) => {
      resolve(pin);
    }));
  }
  const utils_pinDialog = getPinFromDialog;
  var FieldValidationStatus;
  (function(FieldValidationStatus) {
    FieldValidationStatus[FieldValidationStatus["SomeFieldIsEmpty"] = 0] = "SomeFieldIsEmpty";
    FieldValidationStatus[FieldValidationStatus["AllFieldsFilled"] = 1] = "AllFieldsFilled";
  })(FieldValidationStatus || (FieldValidationStatus = {}));
  const validateCredentials = credObjFromStorage => {
    if (credObjFromStorage.username !== "" && credObjFromStorage.password !== "" && credObjFromStorage.q1 !== "Your erp question 1" && credObjFromStorage.q2 !== "Your erp question 2" && credObjFromStorage.q3 !== "Your erp question 3" && credObjFromStorage.a1 !== "" && credObjFromStorage.a2 !== "" && credObjFromStorage.a3 !== "") return FieldValidationStatus.AllFieldsFilled; else return FieldValidationStatus.SomeFieldIsEmpty;
  };
  const utils_validateCredentials = validateCredentials;
  const login = async res => {
    if (!res.authCredentials) {
      utils_displayMessageOnErpLoginPage("You have extension for automatic login. Please fill it", "#715100");
      return;
    }
    const credentials = res.authCredentials;
    if (!credentials.autoLogin) {
      utils_displayMessageOnErpLoginPage("Automatic login is turned off!", "#4a4a4f");
      return;
    }
    const fieldsValidationStatus = utils_validateCredentials(res.authCredentials);
    if (fieldsValidationStatus === FieldValidationStatus.SomeFieldIsEmpty) {
      utils_displayMessageOnErpLoginPage("Please fill all the fields", "#4a4a4f");
      return;
    }
    if (fieldsValidationStatus === FieldValidationStatus.AllFieldsFilled) utils_displayMessageOnErpLoginPage("Prefilling credentials! please wait...");
    const {requirePin, username} = credentials;
    let pin = "";
    if (requirePin) res.useAltPINDialog ? pin = await utils_pinDialog() : pin = prompt("Enter your 4 digit PIN") ?? "";
    let password = "", question = "", answer = "";
    const usernameInput = document.getElementById("user_id");
    const observer = new MutationObserver((async (mutationList, observer) => {
      let [mutation] = mutationList;
      let [node] = mutation.addedNodes;
      question = node.nodeValue;
      observer.disconnect();
      switch (question) {
       case credentials.q1:
        answer = credentials.a1;
        break;

       case credentials.q2:
        answer = credentials.a2;
        break;

       case credentials.q3:
        answer = credentials.a3;
        break;

       default:
        utils_displayMessageOnErpLoginPage("Invalid username/password set! Please update your credentials", "#a4000f");
        return;
      }
      if (requirePin) try {
        password = await decrypt(credentials.password, pin);
        answer = await decrypt(answer, pin);
      } catch (_) {
        utils_displayMessageOnErpLoginPage("Incorrect PIN!, Please reset if forgot or refresh page to retry.", "#a4000f");
        return;
      } else password = credentials.password;
      utils_displayMessageOnErpLoginPage("Prefilling credentials! please wait...");
      let passwordInput = document.getElementById("password");
      let answerInput = document.getElementById("answer");
      if (!passwordInput || !answerInput) {
        utils_displayMessageOnErpLoginPage("Something went wrong! Please refresh page and retry", "#a4000f");
        return;
      }
      passwordInput.value = password;
      answerInput.value = answer;
      utils_displayMessageOnErpLoginPage("Data filled! Click 'Send OTP' to continue", "#4a4a4f");
    }));
    if (usernameInput) {
      observer.observe(document.getElementById("answer_div"), {
        attributes: false,
        childList: true,
        subtree: true
      });
      usernameInput.value = username;
      usernameInput.blur();
    }
  };
  chrome.storage.local.get({
    authCredentials: null,
    landingPage: null,
    useAltPINDialog: false
  }, login);
})();