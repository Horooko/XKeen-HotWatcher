(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  let csrf = "";
  let current = null;
  let sitesDirty = false;
  let activeJob = 0;
  let liveReport = null;
  let lastReport = null;
  let refreshing = false;
  let systemRefreshing = false;
  const pageTitles = { overview: "Обзор подключения", keys: "Управление ключами", "url-test": "Проверка сайтов", system: "XKeen и Xray", updates: "Обновления" };

  async function api(path, options = {}) {
    let response;
    try {
      response = await fetch(path, {
        credentials: "same-origin",
        cache: "no-store",
        ...options,
        headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...(csrf ? { "X-HW-CSRF": csrf } : {}), ...(options.headers || {}) }
      });
    } catch (_) {
      throw new Error("Нет связи с Hot Watcher на роутере. Проверьте сеть и повторите.");
    }
    let data;
    try { data = await response.json(); } catch (_) { throw new Error("Сервер вернул неверный ответ"); }
    if (!response.ok) {
      const error = new Error(data.error || "Не удалось выполнить запрос");
      error.status = response.status;
      if (response.status === 401 && path !== "/api/login" && path !== "/api/session") { csrf = ""; activeJob = 0; showLogin("Панель перезапустилась или сессия завершилась. Войдите снова."); }
      throw error;
    }
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
    navigate();
    refreshSystem();
  }

  function activePage() { const name = location.hash.slice(1); return pageTitles[name] ? name : "overview"; }
  function navigate() {
    const page = activePage();
    for (const section of document.querySelectorAll("[data-page]")) section.hidden = section.dataset.page !== page;
    for (const link of document.querySelectorAll(".nav-link")) link.classList.toggle("active", link.getAttribute("href") === "#" + page);
    text("pageCaption", pageTitles[page]);
    window.scrollTo(0, 0);
    if (csrf && page === "system") refreshSystem();
    if (csrf && page === "updates") refreshUpdate();
  }

  function make(tag, className, content) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (content != null) el.textContent = content;
    return el;
  }
  // FetchedKey is embedded in KeyInventoryEntry. Its JSON fields are lowercase,
  // while the inventory flags keep their Go names. Accept legacy clients too.
  function inventoryKeys(inventory) {
    const keys = Array.isArray(inventory?.Keys) ? inventory.Keys : [];
    return keys.filter((key) => key && typeof key === "object").map((key) => ({
      ...key,
      Tag: String(key.tag ?? key.Tag ?? ""),
      Name: String(key.name ?? key.Name ?? ""),
      Checked: key.checked ?? key.Checked ?? false,
      Verified: key.verified ?? key.Verified ?? false
    }));
  }
  function renderKeys(inventory) {
    const keys = inventoryKeys(inventory);
    const body = $("keysBody");
    const rows = document.createDocumentFragment();
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
      identityWrap.append(make("span", "key-avatar", Array.from(name)[0].toLocaleUpperCase("ru-RU")));
      const identityText = make("span");
      identityText.append(make("strong", "", name + (key.Emergency ? " · Аварийный" : "")), make("small", "mono", key.Tag || "—"));
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
        if (!key.Selected || current?.status?.selection_mode !== "manual") {
          const pin = make("button", "row-button", "Закрепить");
          pin.type = "button";
          pin.addEventListener("click", () => startAction("pin", key.Tag));
          group.append(pin);
        }
      }
      actions.append(group);
      row.append(identity, state, checked, actions);
      rows.append(row);
    }
    body.replaceChildren(rows);
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

  function renderResults(report, running = false) {
    const list = $("resultList");
    list.replaceChildren();
    if (!report || !Array.isArray(report.results) || !report.results.length) {
      list.append(make("div", "result-placeholder", "Запустите URL Test, чтобы увидеть результат по каждому сайту."));
      text("resultTime", "Результата ещё нет");
      text("resultSummary", "Запустите проверку, чтобы увидеть доступность каждого сайта.");
      badge($("resultBadge"), "—", "neutral");
      $("downloadReportButton").disabled = true;
      return;
    }
    text("resultTime", dateLabel(report.time));
    const completed = (report.progress_known || running) ? report.results.filter((item) => item.completed).length : report.results.length;
    const opened = report.results.filter((item) => item.ok).length;
    text("resultSummary", "Проверено " + completed + " из " + report.results.length + " · открывается " + opened + " · не открывается " + (completed - opened));
    badge($("resultBadge"), running ? "Идёт проверка" : completed < report.results.length ? "Прервано" : report.passed ? "Все открылись" : "Есть ошибки", running || completed < report.results.length ? "neutral" : report.passed ? "good" : "bad");
    if (!running) lastReport = report;
    $("downloadReportButton").disabled = running || !lastReport;
    for (const item of report.results) {
      const row = make("div", "result-row" + (item.ok ? " ok" : ""));
      row.append(make("span", "result-dot"), make("span", "result-site", siteName(item.site)));
      const pending = (running || report.progress_known) && !item.completed;
      const detail = pending ? running ? "Ожидает проверки" : "Не проверено" : item.ok ? "Открывается · " + Math.round(item.latency_ms || 0) + " мс" : item.status ? "Не открывается · HTTP " + item.status : "Не открывается · " + (item.reason || "Ошибка");
      row.append(make("span", "result-detail", detail));
      list.append(row);
    }
  }

  function downloadReport() {
    if (!lastReport?.results?.length) return;
    const opened = lastReport.results.filter((item) => item.ok).length;
    const completed = lastReport.progress_known ? lastReport.results.filter((item) => item.completed).length : lastReport.results.length;
    const lines = ["Hot Watcher — отчёт URL Test", "Время: " + new Date(lastReport.time).toLocaleString("ru-RU"), "Ключ: " + (lastReport.tag || "—"), "Проверено: " + completed + " из " + lastReport.results.length, "Открывается: " + opened, ""];
    for (const item of lastReport.results) {
      const outcome = lastReport.progress_known && !item.completed ? "Не проверено" : item.ok ? "Открывается" : "Не открывается";
      lines.push(outcome + " | " + item.site + " | " + (item.status ? "HTTP " + item.status : item.reason || "") + (item.latency_ms != null ? " | " + Math.round(item.latency_ms) + " мс" : ""));
    }
    const link = document.createElement("a");
    const fileURL = URL.createObjectURL(new Blob([lines.join("\n") + "\n"], { type: "text/plain;charset=utf-8" }));
    link.href = fileURL;
    link.download = "hotwatcher-url-test.txt";
    link.click();
    setTimeout(() => URL.revokeObjectURL(fileURL), 1000);
  }

  function renderOverview(data) {
    current = data;
    const status = data.status || {};
    const keys = data.keys || {};
    const list = inventoryKeys(keys);
    const selected = list.find((key) => key.Selected);
    const checked = typeof status.api_reachable === "boolean" && typeof status.balancer_api_reachable === "boolean";
    const online = status.api_reachable === true && status.balancer_api_reachable === true;
    const system = data.system || {};
    const processRunning = system.xray_running;
    text("versionLabel", "v" + (data.version || "—"));
    const xrayLabel = online ? "API доступен" : processRunning === true ? "процесс запущен" : !checked ? "проверяю" : processRunning === false ? "процесс не найден" : "ошибка проверки API";
    text("topStatus", "Xray: " + xrayLabel);
    $("topStatus").className = "top-status" + (online ? " online" : checked && processRunning === false ? " offline" : "");
    badge($("connectionBadge"), online ? "API доступен" : !checked ? "Проверяю" : "Управление недоступно", online ? "good" : "neutral");
    if (data.system) renderSystem(system);
    text("selectedName", selected?.Name || (status.adopted ? "Ключ не найден" : "Не подключено"));
    text("selectedTag", selected?.Tag || status.selected || "—");
    text("apiMetric", online ? "Доступен" : checked ? "Ошибка проверки" : "Проверяю");
    text("apiDetail", online ? "HandlerService и RoutingService доступны. Трафик проверяется через URL Test." : !checked ? "Идёт фоновая проверка API" : processRunning === true ? "Процесс Xray запущен, но API управления недоступен. Это не означает обрыв VPN." : "Проверьте локальный API и службы HandlerService / RoutingService. Состояние трафика не проверено.");
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
    const manual = status.selection_mode === "manual";
    text("modeTitle", manual ? "Закреплённый ключ" : "Автоматический выбор");
    text("modeDescription", manual ? "Hot Watcher не сменит ключ автоматически, даже если проверка обнаружит ошибку." : "Hot Watcher сравнивает задержку и доступность обязательных сайтов.");
    $("pinSelectedButton").disabled = !selected || manual;
    $("autoButton").disabled = !manual;
    const emergency = list.find((key) => key.Emergency);
    text("emergencyCurrent", emergency ? "Добавлен: " + (emergency.Name || emergency.Tag) : "Не добавлен");
    $("forgetEmergencyButton").disabled = !emergency;
    renderKeys(keys);
    renderSites(data.sites || []);
    renderResults(liveReport || data.last_test, !!liveReport);
    const warnings = Array.isArray(data.warnings) ? [...data.warnings] : [];
    if (status.api_error) warnings.push("HandlerService: " + status.api_error);
    if (status.balancer_api_error) warnings.push("RoutingService: " + status.balancer_api_error);
    $("warningList").hidden = warnings.length === 0;
    text("warningList", warnings.join(" · "));
  }

  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
      const data = await api("/api/overview");
      if (csrf) renderOverview(data);
    } catch (error) { showBanner("Не удалось обновить панель", error.message, "failed"); }
    finally { refreshing = false; }
  }
  function renderSystem(state) {
    const checked = !!state.checked_at && !state.checked_at.startsWith("0001");
    const label = !checked ? "Проверяю" : !state.installed ? "Не найден" : state.command_ok ? "Статус получен" : "Установлен, ошибка команды статуса";
    text("xkeenState", label);
    text("xkeenTopStatus", "XKeen: " + (!checked ? "проверяю" : !state.installed ? "не найден" : state.command_ok ? "отвечает" : "установлен"));
    $("xkeenTopStatus").className = "top-status" + (checked && state.command_ok ? " online" : checked && !state.installed ? " offline" : "");
    text("xkeenChecked", checked ? "Проверено: " + dateLabel(state.checked_at) : "Проверка ещё не завершена");
    text("xkeenStatusText", (state.status || []).join("\n") || "Статус пока недоступен");
    text("xkeenLogText", (state.detached_log || []).join("\n") || "Записей пока нет");
    text("xrayLogText", (state.xray_error_log || []).join("\n") || "Записей пока нет");
  }
  async function refreshSystem() {
    if (systemRefreshing) return;
    systemRefreshing = true;
    try {
      const state = await api("/api/system");
      if (csrf) renderSystem(state);
    } catch (error) { showBanner("Статус XKeen", error.message, "failed"); }
    finally { systemRefreshing = false; }
  }
  async function refreshUpdate() {
    try {
      const state = await api("/api/update");
      text("installedVersion", state.installed);
      text("availableVersion", state.available && state.verified ? state.available : "Нет кандидата");
      text("updateMode", !state.enabled ? "Обновления выключены" : state.mode === "auto" ? "Автоустановка" : "Ручная установка");
      text("lastUpdateCheck", state.last_check && !state.last_check.startsWith("0001") ? "Проверено: " + dateLabel(state.last_check) : "Проверка ещё не выполнялась");
      const last = state.last_result;
      text("updateResult", state.state_invalid ? "Состояние повреждено" : state.check_failed ? "Ошибка проверки" : last?.outcome === "installed" ? "Установлена " + last.target : last?.outcome === "rolled_back" ? "Выполнен откат" : last?.outcome === "deferred" ? "Установка " + last.target + " остановлена: " + (last.reason || "проверьте журнал") : "Нет данных");
      text("updatePhase", state.pending_phase ? "Этап: " + state.pending_phase : "Нет текущей установки");
      $("updatePolicy").value = state.policy || "patch";
	  $("enableUpdateButton").hidden = !!state.enabled;
      $("installUpdateButton").disabled = !state.enabled || !state.verified || !state.available || !!state.pending_phase || state.state_invalid;
      $("checkUpdateButton").disabled = !state.enabled || state.state_invalid;
    } catch (error) { showBanner("Обновления", error.message, "failed"); }
  }
  async function startAction(action, tag = "") {
    const names = { sync: "Синхронизация", "check-key": "Проверка ключа", "url-test": "URL Test", select: "Выбор ключа", pin: "Закрепление ключа", auto: "Автовыбор", "forget-emergency": "Аварийный ключ", "update-enable": "Включение обновлений", "update-check": "Проверка обновлений", "update-install": "Установка обновления" };
    try {
      const job = await api("/api/action", { method: "POST", body: JSON.stringify({ action, tag }) });
      activeJob = job.id;
      if (action === "url-test") { liveReport = null; location.hash = "#url-test"; navigate(); }
      showBanner(names[action] || "Операция", action === "update-install" ? "Установщик запущен. Панель может ненадолго перезапуститься." : "Выполняется…");
      await pollJob();
    } catch (error) { showBanner(names[action] || "Операция", error.message, "failed"); }
  }
  async function pollJob() {
    if (!activeJob) return;
    try {
      const job = await api("/api/job");
      if (job.id !== activeJob) return;
      if (job.state === "running") {
        showBanner(job.action === "url-test" ? "URL Test" : "Операция выполняется", job.message);
        if (job.action === "url-test" && job.report?.results?.length) { liveReport = job.report; renderResults(liveReport, true); }
        setTimeout(pollJob, 1200);
        return;
      }
      activeJob = 0;
      liveReport = null;
      showBanner(job.state === "succeeded" ? "Операция завершена" : "Операция не выполнена", job.message, job.state);
      if (job.report?.results?.length) renderResults(job.report);
      await refresh();
      if (activePage() === "updates") await refreshUpdate();
    } catch (error) { if (error.status === 401) return; showBanner("Проверка состояния", error.message, "failed"); setTimeout(pollJob, 2500); }
  }

  async function startEmergency() {
    const uri = $("emergencyInput").value.trim();
    if (!uri.startsWith("vless://")) { showBanner("Аварийный ключ", "Вставьте полный vless:// URI.", "failed"); return; }
    try {
      const job = await api("/api/emergency", { method: "POST", body: JSON.stringify({ uri }) });
      $("emergencyInput").value = "";
      activeJob = job.id;
      showBanner("Аварийный ключ", "Проверяю формат и конфигурацию Xray…");
      await pollJob();
    } catch (error) { showBanner("Аварийный ключ", error.message, "failed"); }
  }

  async function saveUpdatePolicy() {
    try {
      await api("/api/update/policy", { method: "PUT", body: JSON.stringify({ policy: $("updatePolicy").value }) });
      showBanner("Политика обновлений", "Сохранено. Теперь можно проверить релизы.", "succeeded");
      await refreshUpdate();
    } catch (error) { showBanner("Политика обновлений", error.message, "failed"); }
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
  $("downloadReportButton").addEventListener("click", downloadReport);
  $("pinSelectedButton").addEventListener("click", () => { const key = inventoryKeys(current?.keys).find((item) => item.Selected); if (key) startAction("pin", key.Tag); });
  $("autoButton").addEventListener("click", () => startAction("auto"));
  $("emergencyButton").addEventListener("click", startEmergency);
  $("forgetEmergencyButton").addEventListener("click", () => startAction("forget-emergency"));
  $("refreshSystemButton").addEventListener("click", refreshSystem);
	$("enableUpdateButton").addEventListener("click", () => startAction("update-enable"));
  $("checkUpdateButton").addEventListener("click", () => startAction("update-check"));
  $("installUpdateButton").addEventListener("click", () => startAction("update-install"));
  $("savePolicyButton").addEventListener("click", saveUpdatePolicy);
  $("saveSitesButton").addEventListener("click", saveSites);
  $("addSiteButton").addEventListener("click", () => { addSiteRow(); sitesDirty = true; });
  $("keySearch").addEventListener("input", () => renderKeys(current?.keys));
  $("dismissBanner").addEventListener("click", () => { $("operationBanner").hidden = true; });
  window.addEventListener("hashchange", navigate);

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
  // These endpoints read cached health. Editing sites or running a job must not
  // freeze the global indicators; renderSites already preserves unsaved input.
  setInterval(() => { if (csrf && !document.hidden) { refresh(); if (activePage() === "updates" && !activeJob) refreshUpdate(); } }, 5000);
})();
