(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  let csrf = "";
  let current = null;
  let sitesDirty = false;
  let activeJob = 0;

  async function api(path, options = {}) {
    const response = await fetch(path, {
      credentials: "same-origin",
      cache: "no-store",
      ...options,
      headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...(csrf ? { "X-HW-CSRF": csrf } : {}), ...(options.headers || {}) }
    });
    let data;
    try { data = await response.json(); } catch (_) { throw new Error("Сервер вернул неверный ответ"); }
    if (!response.ok) throw new Error(data.error || "Не удалось выполнить запрос");
    return data;
  }

  function text(id, value) { $(id).textContent = value == null || value === "" ? "—" : String(value); }
  function badge(el, label, type) { el.className = "status-badge " + type; el.textContent = label; }
  function siteName(value) { return String(value || "").replace(/^https:\/\//, "").replace(/\/$/, ""); }
  function timeAgo(nanoseconds) {
    if (nanoseconds == null) return "нет данных";
    const seconds = Math.max(0, Math.floor(Number(nanoseconds) / 1e9));
    if (seconds < 60) return "только что";
    if (seconds < 3600) return Math.floor(seconds / 60) + " мин назад";
    if (seconds < 86400) return Math.floor(seconds / 3600) + " ч назад";
    return Math.floor(seconds / 86400) + " д назад";
  }
  function dateLabel(value) {
    if (!value) return "Результата ещё нет";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "Результата ещё нет" : date.toLocaleString("ru-RU", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
  }
  function showBanner(title, message, state = "running") {
    const box = $("operationBanner");
    box.hidden = false;
    box.className = "operation-banner " + state;
    text("operationTitle", title);
    text("operationMessage", message);
    text("operationIcon", state === "succeeded" ? "✓" : state === "failed" ? "!" : "↻");
  }
  function showLogin(error) {
    $("loginScreen").hidden = false;
    $("appScreen").hidden = true;
    if (error) { $("loginError").hidden = false; text("loginError", error); }
    $("tokenInput").focus();
  }
  function showApp() {
    $("loginScreen").hidden = true;
    $("appScreen").hidden = false;
  }

  function make(tag, className, content) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (content != null) el.textContent = content;
    return el;
  }
  function renderKeys(inventory) {
    const keys = Array.isArray(inventory?.Keys) ? inventory.Keys : [];
    const body = $("keysBody");
    body.replaceChildren();
    text("keyCount", keys.length + " КЛЮЧЕЙ");
    text("keysNote", inventory?.Note || "Из сохранённого состояния");
    const query = $("keySearch").value.trim().toLocaleLowerCase("ru-RU");
    let visible = 0;
    for (const key of keys) {
      const name = key.Name || key.Tag || "Без имени";
      if (query && !(name + " " + key.Tag).toLocaleLowerCase("ru-RU").includes(query)) continue;
      visible++;
      const row = make("tr");
      const identity = make("td");
      const identityWrap = make("div", "key-name");
      identityWrap.append(make("span", "key-avatar", name.slice(0, 1).toLocaleUpperCase("ru-RU")));
      const identityText = make("span");
      identityText.append(make("strong", "", name), make("small mono", key.Tag || "—"));
      identityWrap.append(identityText); identity.append(identityWrap);
      const state = make("td");
      state.append(make("span", "pill " + (key.Selected ? "" : key.Applied ? "muted" : "warning"), key.Selected ? "Выбран" : key.Applied ? "Применён" : "Не применён"));
      const checked = make("td");
      checked.append(make("span", "pill " + (key.Verified ? "" : key.Checked ? "bad" : "muted"), key.Verified ? "Проверен без VPN" : key.Checked ? "Не прошёл" : "Нет данных"));
      const actions = make("td", "actions-col");
      const group = make("div", "inline-actions");
      if (key.Applied) {
        const test = make("button", "row-button", "URL Test");
        test.type = "button";
        test.addEventListener("click", () => startAction("url-test", key.Tag));
        group.append(test);
        if (!key.Selected) {
          const select = make("button", "row-button select", "Выбрать");
          select.type = "button";
          select.addEventListener("click", () => startAction("select", key.Tag));
          group.append(select);
        }
      }
      actions.append(group);
      row.append(identity, state, checked, actions);
      body.append(row);
    }
    $("keysEmpty").hidden = visible !== 0;
  }

  function addSiteRow(value = "") {
    const rows = $("siteRows");
    if (rows.children.length >= 12) return;
    const row = make("div", "site-row");
    const index = make("span", "site-index", String(rows.children.length + 1).padStart(2, "0"));
    const prefix = make("span", "site-prefix mono", "https://");
    const input = make("input", "site-input");
    input.type = "text";
    input.value = siteName(value);
    input.placeholder = "example.com";
    input.autocomplete = "off";
    input.spellcheck = false;
    input.setAttribute("aria-label", "Домен сайта " + (rows.children.length + 1));
    input.addEventListener("input", () => { sitesDirty = true; });
    const remove = make("button", "site-remove", "×");
    remove.type = "button";
    remove.setAttribute("aria-label", "Удалить сайт");
    remove.addEventListener("click", () => { row.remove(); sitesDirty = true; updateSiteCount(); });
    row.append(index, prefix, input, remove);
    rows.append(row);
    updateSiteCount();
    if (!value) input.focus();
  }
  function updateSiteCount() {
    const rows = [...$("siteRows").children];
    rows.forEach((row, i) => { row.querySelector(".site-index").textContent = String(i + 1).padStart(2, "0"); });
    text("siteCount", rows.length + " / 12");
  }
  function renderSites(sites) {
    if (sitesDirty) return;
    $("siteRows").replaceChildren();
    for (const site of sites || []) addSiteRow(site);
    sitesDirty = false;
  }
  async function saveSites() {
    const sites = [...$("siteRows").querySelectorAll(".site-input")].map((el) => el.value.trim());
    if (sites.some((s) => !s)) { showBanner("Список сайтов", "Заполните каждый домен или удалите пустую строку.", "failed"); return; }
    try {
      const saved = await api("/api/sites", { method: "PUT", body: JSON.stringify({ sites }) });
      sitesDirty = false;
      renderSites(saved.sites);
      showBanner("Список сохранён", "Новые проверки будут использовать обновлённые сайты.", "succeeded");
      await refresh();
    } catch (error) { showBanner("Не удалось сохранить", error.message, "failed"); }
  }

  function renderResults(report) {
    const list = $("resultList");
    list.replaceChildren();
    if (!report || !Array.isArray(report.results) || !report.results.length) {
      list.append(make("div", "result-placeholder", "Запустите URL Test, чтобы увидеть результат по каждому сайту."));
      text("resultTime", "Результата ещё нет");
      badge($("resultBadge"), "—", "neutral");
      return;
    }
    text("resultTime", dateLabel(report.time));
    badge($("resultBadge"), report.passed ? "Все открылись" : "Есть ошибки", report.passed ? "good" : "bad");
    for (const item of report.results) {
      const row = make("div", "result-row" + (item.ok ? " ok" : ""));
      row.append(make("span", "result-dot"), make("span", "result-site", siteName(item.site)));
      const detail = item.ok ? Math.round(item.latency_ms || 0) + " мс" : item.status ? "HTTP " + item.status : item.reason || "Ошибка";
      row.append(make("span", "result-detail", detail));
      list.append(row);
    }
  }

  function renderOverview(data) {
    current = data;
    const status = data.status || {};
    const keys = data.keys || {};
    const list = Array.isArray(keys.Keys) ? keys.Keys : [];
    const selected = list.find((key) => key.Selected);
    const online = !!status.api_reachable && !!status.balancer_api_reachable;
    text("versionLabel", "v" + (data.version || "—"));
    text("topStatus", online ? "Xray работает" : "Xray недоступен");
    $("topStatus").className = "top-status " + (online ? "online" : "offline");
    badge($("connectionBadge"), online ? "Активно" : "Нет связи", online ? "good" : "bad");
    text("selectedName", selected?.Name || (status.adopted ? "Ключ не найден" : "Не подключено"));
    text("selectedTag", selected?.Tag || status.selected || "—");
    text("apiMetric", online ? "Работает" : "Нет связи");
    text("apiDetail", online ? "API и балансировщик доступны" : "Проверьте XKeen и Xray");
    text("keyMetric", String(status.active_nodes ?? list.filter((item) => item.Applied).length));
    text("testMetric", String((data.sites || []).length));
    text("testDetail", "Обязательных сайтов");
    text("syncMetric", timeAgo(keys.LastCheckAgo));
    text("syncDetail", keys.LastCheckSuccess === false ? "Последняя проверка с ошибкой" : "Последняя проверка подписки");
    text("configState", status.disk_matches_state === true ? "Согласована" : status.adopted ? "Нужна проверка" : "Не настроена");
    text("configDetail", status.disk_matches_state === true ? "Файл ключей совпадает с сохранённым состоянием" : "Откройте hotwatcher status в терминале");
    const recovery = data.recovery || {};
    const interrupted = !!recovery.pending_transaction || !!recovery.hard_sync;
    text("recoveryState", interrupted ? "Нужны действия" : "В норме");
    text("recoveryDetail", recovery.suggested_command || "Незавершённых операций нет");
    renderKeys(keys);
    renderSites(data.sites || []);
    renderResults(data.last_test);
    const warnings = Array.isArray(data.warnings) ? data.warnings : [];
    $("warningList").hidden = warnings.length === 0;
    text("warningList", warnings.join(" · "));
  }

  async function refresh() {
    try { renderOverview(await api("/api/overview")); }
    catch (error) { showBanner("Не удалось обновить панель", error.message, "failed"); }
  }
  async function startAction(action, tag = "") {
    const names = { sync: "Синхронизация", "check-key": "Проверка ключа", "url-test": "URL Test", select: "Выбор ключа" };
    try {
      const job = await api("/api/action", { method: "POST", body: JSON.stringify({ action, tag }) });
      activeJob = job.id;
      showBanner(names[action] || "Операция", "Проверка выполняется. Подключение остаётся на старом ключе до успешного результата.");
      await pollJob();
    } catch (error) { showBanner(names[action] || "Операция", error.message, "failed"); }
  }
  async function pollJob() {
    if (!activeJob) return;
    try {
      const job = await api("/api/job");
      if (job.id !== activeJob) return;
      if (job.state === "running") { setTimeout(pollJob, 1200); return; }
      activeJob = 0;
      showBanner(job.state === "succeeded" ? "Операция завершена" : "Операция не выполнена", job.message, job.state);
      if (job.report?.results?.length) renderResults(job.report);
      await refresh();
    } catch (error) { showBanner("Проверка состояния", error.message, "failed"); setTimeout(pollJob, 2500); }
  }

  $("loginForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    $("loginError").hidden = true;
    try {
      const data = await api("/api/login", { method: "POST", body: JSON.stringify({ token: $("tokenInput").value }) });
      csrf = data.csrf;
      $("tokenInput").value = "";
      showApp();
      await refresh();
    } catch (error) { $("loginError").hidden = false; text("loginError", error.message); }
  });
  $("logoutButton").addEventListener("click", async () => { try { await api("/api/logout", { method: "POST", body: "{}" }); } catch (_) {} csrf = ""; showLogin(); });
  $("syncButton").addEventListener("click", () => startAction("sync"));
  $("checkButton").addEventListener("click", () => startAction("check-key"));
  $("testSelectedButton").addEventListener("click", () => startAction("url-test"));
  $("saveSitesButton").addEventListener("click", saveSites);
  $("addSiteButton").addEventListener("click", () => { addSiteRow(); sitesDirty = true; });
  $("keySearch").addEventListener("input", () => renderKeys(current?.keys));
  $("dismissBanner").addEventListener("click", () => { $("operationBanner").hidden = true; });
  for (const link of document.querySelectorAll(".nav-link")) {
    link.addEventListener("click", () => {
      document.querySelectorAll(".nav-link").forEach((item) => item.classList.remove("active"));
      link.classList.add("active");
    });
  }

  (async () => {
    try {
      const session = await api("/api/session");
      if (session.authenticated) {
        csrf = session.csrf;
        showApp();
        await refresh();
        const job = await api("/api/job");
        if (job.state === "running") { activeJob = job.id; showBanner("Операция выполняется", job.message); pollJob(); }
      } else showLogin();
    } catch (error) { showLogin(error.message); }
  })();
  setInterval(() => { if (csrf && !activeJob && !sitesDirty) refresh(); }, 30000);
})();
