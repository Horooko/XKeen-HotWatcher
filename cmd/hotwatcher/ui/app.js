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
  let activityRefreshing = false;
  let currentActivity = null;
  let webJob = null;
  let dnsRefreshing = false;
  let dnsCatalog = [];
  let dnsCatalogDirty = false;
  let previousLAN = null;
  let currentLAN = null;
  let statusReport = null;
  let statusReportLoading = false;
  const pageTitles = { overview: "Обзор подключения", keys: "Управление ключами", "url-test": "Проверка сайтов", dns: "DNS Xray", statuses: "Отчёт о состоянии", system: "XKeen и Xray", updates: "Обновления" };

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
  function elapsedLabel(value) {
    const seconds = Math.max(0, Math.floor(Number(value)));
    if (!Number.isFinite(seconds)) return "—";
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor(seconds % 3600 / 60);
    const rest = seconds % 60;
    return (hours ? hours + " ч " : "") + (hours || minutes ? minutes + " мин " : "") + rest + " сек";
  }
  function renderActivity(state) {
    currentActivity = state;
    const lock = state?.lock || {};
    const busy = lock.busy === true;
    const paused = state?.background_paused === true;
    const stopRequested = state?.stop_requested === true;
    const serverJob = state?.web_job && ["queued", "waiting", "running"].includes(state.web_job.state) ? state.web_job : null;
    const localJob = webJob && ["queued", "waiting", "running"].includes(webJob.state) ? webJob : null;
    const visibleJob = serverJob || localJob;
    text("activityState", busy ? (stopRequested ? "Завершает перед паузой: " : "Выполняется: ") + (lock.operation || "операция") : visibleJob ? "Задача панели: " + (visibleJob.action || "операция") : paused ? "Фоновые задачи приостановлены" : "Нет операции под общей блокировкой");
    text("activityMessage", state?.message || (busy ? "Ожидайте завершения текущей операции." : visibleJob ? "Задача выполняется или ожидает блокировки." : paused ? "Новые фоновые задачи не запускаются." : "Задачи панели без блокировки могут выполняться отдельно."));
    text("activityElapsed", busy ? elapsedLabel(state?.elapsed_seconds) : serverJob ? elapsedLabel(serverJob.elapsed_seconds) : "—");
    $("activityWebJob").hidden = !visibleJob;
    if (visibleJob) {
      const sameLocalJob = serverJob && localJob?.id === serverJob.id;
      const detail = serverJob ? sameLocalJob ? localJob.message : "выполняется или ожидает блокировки" : localJob.message || "ожидает завершения";
      text("activityWebJob", (visibleJob.state === "running" ? "Запрос из панели: " : "В очереди панели: ") + (visibleJob.action || "операция") + " · " + detail + (busy && serverJob ? " · " + elapsedLabel(serverJob.elapsed_seconds) : ""));
    }
    $("stopActivityButton").disabled = state?.can_stop !== true || paused || stopRequested;
    $("resumeActivityButton").hidden = !paused;
    $("resumeActivityButton").disabled = !paused;
  }
  async function refreshActivity() {
    if (activityRefreshing) return;
    activityRefreshing = true;
    try { renderActivity(await api("/api/activity")); }
    catch (error) {
      if (error.status !== 401) {
        text("activityState", "Состояние операций недоступно");
        text("activityMessage", error.message);
        text("activityElapsed", "—");
        $("stopActivityButton").disabled = true;
        $("resumeActivityButton").hidden = true;
      }
    } finally { activityRefreshing = false; }
  }
  async function controlActivity(path, title) {
    $("stopActivityButton").disabled = true;
    $("resumeActivityButton").disabled = true;
    try {
      const result = await api(path, { method: "POST", body: "{}" });
      showBanner(title, result.message || "Состояние фоновых задач обновлено.", "succeeded");
    } catch (error) { showBanner(title, error.message, "failed"); }
    await refreshActivity();
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
    dnsCatalogDirty = false;
    currentLAN = null;
    previousLAN = null;
    statusReport = null;
    $("statusReportActions").hidden = true;
    $("statusReportSections").replaceChildren();
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
    refreshActivity();
  }

  function activePage() { const name = location.hash.slice(1); return pageTitles[name] ? name : "overview"; }
  function navigate() {
    const page = activePage();
    for (const section of document.querySelectorAll("[data-page]")) section.hidden = section.dataset.page !== page;
    for (const link of document.querySelectorAll(".nav-link")) link.classList.toggle("active", link.getAttribute("href") === "#" + page);
    text("pageCaption", pageTitles[page]);
    window.scrollTo(0, 0);
    if (csrf && page === "system") refreshSystem();
    if (csrf && page === "system") refreshActivity();
    if (csrf && page === "dns") refreshDNS();
    if (csrf && page === "updates") refreshUpdate();
  }

  function make(tag, className, content) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (content != null) el.textContent = content;
    return el;
  }
  function renderStatusReport(report) {
    const checklist = $("statusReportChecklist");
    checklist.replaceChildren();
    const checks = Array.isArray(report.checks) ? report.checks : [];
    if (checks.length) {
      const counts = { ok: 0, issue: 0, unknown: 0, info: 0 };
      const groups = new Map();
      for (const check of checks) {
        const state = Object.hasOwn(counts, check.state) ? check.state : "info";
        counts[state]++;
        const name = check.group || "Прочее";
        if (!groups.has(name)) groups.set(name, []);
        groups.get(name).push({ ...check, state });
      }
      const summary = make("div", "status-check-summary");
      for (const [state, label] of [["ok", "Пройдено"], ["issue", "Требует внимания"], ["unknown", "Нет данных"], ["info", "Информация"]]) {
        const item = make("div", "status-check-count " + state);
        item.append(make("strong", "", String(counts[state])), make("span", "", label));
        summary.append(item);
      }
      checklist.append(summary);
      for (const [name, items] of groups) {
        const group = make("section", "panel status-check-group");
        group.append(make("h3", "", name));
        const list = make("div", "status-check-list");
        for (const check of items) {
          const row = make("div", "status-check-row " + check.state);
          const icon = make("span", "status-check-icon", check.state === "ok" ? "✓" : check.state === "issue" ? "!" : check.state === "unknown" ? "?" : "i");
          icon.setAttribute("aria-hidden", "true");
          const body = make("div", "status-check-body");
          body.append(make("strong", "", check.title || "Проверка"));
          if (check.detail) body.append(make("p", "", check.detail));
          row.append(icon, body, make("span", "status-check-label", check.state === "ok" ? "ОК" : check.state === "issue" ? "ПРОБЛЕМА" : check.state === "unknown" ? "НЕТ ДАННЫХ" : "СВЕДЕНИЯ"));
          list.append(row);
        }
        group.append(list);
        checklist.append(group);
      }
    }
    checklist.hidden = !checks.length;
    const sections = $("statusReportSections");
    sections.replaceChildren();
    for (const section of Array.isArray(report.sections) ? report.sections : []) {
      const card = make("section", "panel status-report-section");
      card.append(make("h3", "", section.title || "Раздел"));
      card.append(make("pre", "", Array.isArray(section.lines) ? section.lines.join("\n") : "Нет данных"));
      sections.append(card);
    }
    const details = $("statusReportDetails");
    details.hidden = !sections.children.length;
    details.open = !checks.length;
    text("statusReportState", "Собран " + dateLabel(report.generated_at) + " · " + checks.length + " проверок · " + sections.children.length + " разделов. Снимок не обновляется автоматически.");
    $("statusReportActions").hidden = false;
  }
  async function generateStatusReport() {
    if (statusReportLoading) return;
    statusReportLoading = true;
    statusReport = null;
    $("statusReportActions").hidden = true;
    $("statusReportChecklist").hidden = true;
    $("statusReportChecklist").replaceChildren();
    $("statusReportDetails").hidden = true;
    $("statusReportSections").replaceChildren();
    $("generateStatusReportButton").disabled = true;
    text("statusReportState", "Собираю отчёт. Проверка выбранного ключа может занять несколько секунд…");
    try {
      const report = await api("/api/diagnostics/report");
      if (!Array.isArray(report.sections) || typeof report.text !== "string") throw new Error("Сервер вернул неполный отчёт");
      statusReport = report;
      renderStatusReport(report);
    } catch (error) {
      text("statusReportState", "Не удалось собрать отчёт: " + error.message);
      if (error.status !== 401) showBanner("Отчёт о состоянии", error.message, "failed");
    } finally { statusReportLoading = false; $("generateStatusReportButton").disabled = false; }
  }
  function downloadStatusReport(format) {
    if (!statusReport) return;
    const content = format === "json" ? JSON.stringify(statusReport, null, 2) + "\n" : statusReport.text;
    const filename = "hotwatcher-status-" + String(statusReport.generated_at || "report").slice(0, 19).replace(/[^0-9A-Za-z]/g, "-") + "." + format;
    const link = document.createElement("a");
    const fileURL = URL.createObjectURL(new Blob([content], { type: format === "json" ? "application/json;charset=utf-8" : "text/plain;charset=utf-8" }));
    link.href = fileURL;
    link.download = filename;
    link.click();
    setTimeout(() => URL.revokeObjectURL(fileURL), 1000);
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
    const live = current?.status?.api_reachable === true && current?.status?.balancer_api_reachable === true && current?.status?.selected_present === true && current?.status?.balancer_pin_matches === true && current?.system?.xray_running === true;
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
      identityText.append(make("strong", "", name + (key.Emergency ? " · Аварийная пометка" : "")), make("small", "mono", key.Tag || "—"));
      identityWrap.append(identityText); identity.append(identityWrap);
      const state = make("td");
      state.append(make("span", "pill " + (key.Selected && live ? "" : key.Applied ? "muted" : "warning"), key.Selected ? (live ? "Выбран в Xray" : "Сохранённый выбор") : key.Applied ? "В файле" : "Не применён"));
      const checked = make("td");
      checked.append(make("span", "pill " + (key.Verified ? "" : key.Checked ? "bad" : "muted"), key.Verified ? "Проверен без VPN" : key.Checked ? "Не прошёл" : "Нет данных"));
      const actions = make("td", "actions-col");
      const group = make("div", "inline-actions");
      if (key.Applied) {
        if (key.Selected || current?.economy_checks === false) {
          const test = make("button", "row-button", "URL Test");
          test.type = "button";
          test.addEventListener("click", () => startAction("url-test", key.Tag));
          group.append(test);
        }
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
    const route = report.mode === "main_xray" ? " · основной Xray" : report.mode === "isolated" ? " · отдельный Xray" : "";
    text("resultSummary", "Проверено " + completed + " из " + report.results.length + " · HTTPS-ответ " + opened + " · ошибка проверки " + (completed - opened) + route + " · маршрут устройств в сети не проверен");
    badge($("resultBadge"), running ? "Идёт проверка" : completed < report.results.length ? "Прервано" : report.passed ? "Все проверки прошли" : "Есть ошибки", running || completed < report.results.length ? "neutral" : report.passed ? "good" : "bad");
    if (!running) lastReport = report;
    $("downloadReportButton").disabled = running || !lastReport;
    for (const item of report.results) {
      const row = make("div", "result-row" + (item.ok ? " ok" : ""));
      row.append(make("span", "result-dot"), make("span", "result-site", siteName(item.site)));
      const pending = (running || report.progress_known) && !item.completed;
      const detail = pending ? running ? "Ожидает проверки" : "Не проверено" : item.ok ? "HTTPS-ответ · " + Math.round(item.latency_ms || 0) + " мс" : "Проверка не прошла · " + (item.reason || (item.status ? "HTTP " + item.status : "Ошибка")) + (item.reason && item.status ? " · HTTP " + item.status : "");
      row.append(make("span", "result-detail", detail));
      list.append(row);
    }
  }

  function downloadReport() {
    if (!lastReport?.results?.length) return;
    const opened = lastReport.results.filter((item) => item.ok).length;
    const completed = lastReport.progress_known ? lastReport.results.filter((item) => item.completed).length : lastReport.results.length;
    const lines = ["Hot Watcher — отчёт URL Test", "Время: " + new Date(lastReport.time).toLocaleString("ru-RU"), "Ключ: " + (lastReport.tag || "—"), "Режим: " + (lastReport.mode === "main_xray" ? "основной Xray" : lastReport.mode === "isolated" ? "отдельный Xray" : "не указан"), "Проверено: " + completed + " из " + lastReport.results.length, "Успешных HTTPS-проверок: " + opened, "Маршрут устройств в сети, их DNS и перехват трафика XKeen не проверены.", ""];
    for (const item of lastReport.results) {
      const outcome = lastReport.progress_known && !item.completed ? "Не проверено" : item.ok ? "HTTPS-проверка успешна" : "HTTPS-проверка не прошла";
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
    $("economyChecks").checked = data.economy_checks === true;
    $("economyChecks").disabled = data.live_probes_allowed !== true;
    text("probeModeNote", data.live_probes_allowed !== true ? "Проверки изолированы от рабочего Xray. Режим с изменением живых правил доступен только при явном allow_live_probes в локальном конфиге." : data.economy_checks === true ? "Проверка временно меняет правила основного Xray; используйте только при осознанной необходимости." : "Отдельный Xray проверяет выбранный ключ; рабочие правила маршрутизации не меняются.");
    const status = data.status || {};
    const keys = data.keys || {};
    const list = inventoryKeys(keys);
    const selected = list.find((key) => key.Selected);
    const checked = typeof status.api_reachable === "boolean" && typeof status.balancer_api_reachable === "boolean";
    const online = status.api_reachable === true && status.balancer_api_reachable === true;
    const system = data.system || {};
    const processRunning = system.xray_running;
    text("versionLabel", "v" + (data.version || "—"));
    const xrayLabel = processRunning === false ? "процесс не найден" : online ? processRunning === true ? "API доступен" : "API доступен; процесс не подтверждён" : processRunning === true ? "процесс запущен" : !checked ? "проверяю" : "ошибка проверки API";
    text("topStatus", "Xray: " + xrayLabel);
    $("topStatus").className = "top-status" + (online && processRunning === true ? " online" : checked && processRunning === false ? " offline" : "");
    badge($("connectionBadge"), online ? processRunning === true ? "API доступен" : "API доступен · процесс не подтверждён" : !checked ? "Проверяю" : "Управление недоступно", online && processRunning === true ? "good" : "neutral");
    if (data.system) renderSystem(system);
    const pinMismatch = online && status.adopted && (status.selected_present === false || status.balancer_pin_matches === false);
    const lanMissing = currentLAN?.tcp?.known === true && currentLAN?.tcp?.present === false && currentLAN?.udp?.known === true && currentLAN?.udp?.present === false;
    const diagnosis = !checked ? "Проверяю процесс Xray и API." : processRunning === false ? "Xray не запущен. Выбранный ключ сохранён в файле, но сейчас не обслуживает трафик. Проверьте запуск XKeen и ошибки Xray." : processRunning !== true ? "Основной процесс Xray не удалось подтвердить. Даже если API отвечает, состояние ключа и маршрута пока неизвестно." : lanMissing ? "Перехват трафика LAN отсутствует: правила XKeen не направляют соединения устройств в Xray. Откройте «Система» и восстановите правила XKeen. Проверки ключей и DNS эту проблему не исправят." : !online ? "Xray запущен, но API управления недоступен. Проверка ключа через HotWatcher невозможна; проверьте конфигурацию API." : pinMismatch ? "Xray запущен, но сохранённый ключ сейчас не закреплён в балансировщике. Выполните «Согласовать Xray» и проверьте отдельные HTTPS-адреса." : "Xray и API управления доступны. URL Test проверяет только отдельные HTTPS-адреса; работу приложений он не подтверждает.";
    text("systemDiagnosis", diagnosis);
    $("systemDiagnosis").className = "system-diagnosis" + (checked && (processRunning === false || lanMissing || !online || pinMismatch) ? " failed" : checked && online && processRunning === true ? " ready" : "");
    text("selectedName", selected?.Name || (status.adopted ? "Ключ не найден" : "Не подключено"));
    text("selectedTag", selected?.Tag || status.selected || "—");
    $("selectedOrigin").hidden = !selected?.Emergency;
    text("apiMetric", online ? "Доступен" : checked ? "Ошибка проверки" : "Проверяю");
    text("apiDetail", online ? "HandlerService и RoutingService доступны. Работа приложений этим не подтверждена." : !checked ? "Идёт фоновая проверка API" : processRunning === true ? "Процесс Xray запущен, но API управления недоступен. Это не означает обрыв VPN." : "Проверьте локальный API и службы HandlerService / RoutingService. Состояние трафика не проверено.");
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
    text("holdState", status.hold ? "Обновление подписки приостановлено" : "Фоновая синхронизация включена");
    $("holdOnButton").disabled = !!status.hold;
    $("holdOffButton").disabled = !status.hold;
    $("adoptButton").disabled = !!status.adopted;
    $("recoverButton").disabled = !recovery.pending_transaction || !!recovery.hard_sync;
    $("abortButton").disabled = !recovery.pending_transaction || !!recovery.hard_sync;
    const manual = status.selection_mode === "manual";
    text("modeTitle", manual ? "Закреплён вручную" : "Автовыбор включён");
    text("modeDescription", manual ? "Текущий ключ закреплён вручную; фоновая синхронизация и проверки приостановлены. При ошибке проверки включение Auto не снимет закрепление." : "Текущий ключ сохраняется, пока другой не пройдёт проверки и условия переключения. Повторная проверка всех ключей может занять несколько минут и тоже оставить прежний выбор.");
    $("pinSelectedButton").disabled = !selected || manual;
    text("autoButton", manual ? "Включить автовыбор" : "Повторить выбор");
    $("autoButton").disabled = !status.adopted;
    const emergency = list.find((key) => key.Emergency);
    text("emergencyCurrent", emergency ? "Сохранён: " + (emergency.Name || emergency.Tag) + (emergency.Selected ? " · сейчас выбран" : " · сейчас не выбран") : "Аварийной пометки нет");
    $("forgetEmergencyButton").disabled = !emergency;
    const keyWarnings = [];
    if (recovery.pending_transaction) keyWarnings.push("Есть незавершённое применение ключей. До завершения или отмены транзакции смена ключа и автовыбор заблокированы.");
    if (recovery.hard_sync) keyWarnings.push("Сохранился журнал hard-sync" + (recovery.hard_sync.stage ? " (этап: " + recovery.hard_sync.stage + ")" : "") + ". Сам этот журнал не блокирует смену ключа и не подтверждает работу прокси. " + (recovery.suggested_command ? "Состояние: " + recovery.suggested_command + ". " : ""));
    if (keys.LastCheckSuccess === false) keyWarnings.push("Последняя синхронизация завершилась ошибкой; сохранённый список ключей не подтверждает успешные проверки.");
    if (list.length && !list.some((key) => key.Checked || key.Verified)) keyWarnings.push("У всех " + list.length + " ключей нет результатов проверки. «Нет данных» не означает, что ключи не работают.");
    $("keysWarning").hidden = keyWarnings.length === 0;
    if (keyWarnings.length) text("keysWarning", keyWarnings.join(" "));
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
  function renderLAN(lan) {
    if (!lan) return;
    currentLAN = lan;
    const previous = previousLAN && previousLAN.checked_at !== lan.checked_at ? previousLAN : null;
    const reasons = { xray_inbound_unknown: "Не найден подходящий вход Xray в 03_inbounds.json", iptables_save_unavailable: "iptables-save недоступен", rules_unavailable: "Не удалось прочитать правила", xkeen_chain_missing: "Цепочка xkeen не найдена в проверенном наборе правил", prerouting_jump_missing: "Нет перехода из PREROUTING", redirect_target_missing: "Нет перенаправления на порт Xray", route_disconnected: "Правило не связано с входом LAN" };
    text("lanChecked", "Правила проверены: " + dateLabel(lan.checked_at) + ". Счётчики суммарные для всей сети.");
    for (const [name, key] of [["TCP", "tcp"], ["UDP", "udp"], ["IPv6TCP", "tcp_ipv6"], ["IPv6UDP", "udp_ipv6"]]) {
      const path = lan[key] || {};
      const before = previous?.[key];
      text("lan" + name + "State", !path.known ? "Проверка недоступна" : path.present ? "Правило найдено" : "Правило отсутствует");
      let detail = path.missing ? reasons[path.missing] || "Правило не подтверждено" : "Порт Xray: " + (path.expected_port || "?");
      if (path.known) {
        detail += ". Пакеты: вход " + (path.ingress_packets ?? 0) + ", в Xray " + (path.redirected_packets ?? 0);
        if (before && before.known && Number(path.redirected_packets) >= Number(before.redirected_packets)) detail += "; с прошлого снимка +" + (Number(path.redirected_packets) - Number(before.redirected_packets));
      }
      text("lan" + name + "Detail", detail);
    }
    if (!previousLAN || previousLAN.checked_at !== lan.checked_at) previousLAN = lan;
    $("repairLANButton").disabled = !["tcp", "udp", "tcp_ipv6", "udp_ipv6"].some(key => lan[key]?.known === true && lan[key]?.present === false) || current?.system?.xray_running !== true;
  }
  function renderSystem(state) {
    const checked = !!state.checked_at && !state.checked_at.startsWith("0001");
    const lan = state.lan_interception || currentLAN;
    const lanMissing = lan?.tcp?.known === true && lan?.tcp?.present === false && lan?.udp?.known === true && lan?.udp?.present === false;
    const label = !checked ? "Проверяю" : !state.installed ? "Не найден" : lanMissing ? "Нет перехвата LAN" : state.command_ok ? "Статус получен" : "Установлен, ошибка команды статуса";
    text("xkeenState", state.xray_running === false ? "Xray остановлен" : label);
    text("xkeenTopStatus", "XKeen: " + (!checked ? "проверяю" : !state.installed ? "не найден" : state.xray_running === false ? "Xray остановлен" : lanMissing ? "нет перехвата LAN" : state.command_ok ? "команда доступна" : "ошибка статуса"));
    $("xkeenTopStatus").className = "top-status" + (checked && (state.xray_running === false || !state.installed || lanMissing) ? " offline" : "");
    text("xkeenChecked", checked ? "Проверено: " + dateLabel(state.checked_at) : "Проверка ещё не завершена");
    text("xkeenStatusText", (state.status || []).join("\n") || "Статус пока недоступен");
    text("xkeenLogText", (state.detached_log || []).join("\n") || "Фоновых команд start/stop нет.");
    const logSettingsUnknown = state.xray_log_config_known === false;
    const errorPathUnknown = logSettingsUnknown || state.xray_error_path_known === false;
    const accessPathUnknown = logSettingsUnknown || state.xray_access_path_known === false;
    text("xrayLogDetail", (errorPathUnknown ? "Путь не определён" : state.xray_error_path || "Файл отключён") + (state.xray_log_level ? " · уровень " + state.xray_log_level : " · уровень неизвестен"));
    text("xrayLogText", (state.xray_error_log || []).join("\n") || (logSettingsUnknown ? "Не удалось прочитать настройки журнала Xray." : errorPathUnknown ? "Путь журнала ошибок в конфигурации Xray не распознан." : state.xray_log_level === "none" ? "Журнал ошибок отключён в конфигурации Xray: loglevel = none." : !state.xray_error_path ? "Запись в файл отключена в конфигурации Xray." : "Журнал ошибок пуст или не создан. Это не подтверждает исправность Xray."));
    text("xrayAccessLogDetail", accessPathUnknown ? "Путь не определён" : state.xray_access_path || "Файл отключён");
    text("xrayAccessLogText", (state.xray_access_log || []).join("\n") || (logSettingsUnknown ? "Не удалось прочитать настройки журнала Xray." : accessPathUnknown ? "Путь журнала доступа в конфигурации Xray не распознан." : !state.xray_access_path ? "Журнал доступа отключён в конфигурации Xray." : "Журнал доступа пуст или не создан."));
    renderLAN(lan);
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
  function renderDNS(state) {
    text("dnsConfigFile", state.generated_config_file || state.config_file || "DNS-фрагмент не найден");
    badge($("dnsBadge"), state.managed ? "DNS auto подготовлен" : "Ручная конфигурация", state.managed ? "good" : "neutral");
    text("dnsServers", "Серверы: " + (state.servers?.length ? state.servers.join(", ") : "не указаны"));
    text("dnsAppliedProviders", "Выбраны проверкой: " + (state.applied_provider_ids?.length ? state.applied_provider_ids.join(", ") : "—"));
    text("dnsParallel", "Параллельные запросы: " + (state.parallel_queries ? "включены" : "выключены"));
    text("dnsNote", state.note || (state.runtime_activation_unverified ? "Неизвестно, загрузил ли работающий Xray изменения. Требуется ручной перезапуск." : "Показано состояние файла Xray."));
    dnsCatalog = state.providers || [];
    const catalogLines = ["# Удалите # только у поддерживаемых адресов; неизвестные и несовместимые адреса отклоняются."];
    let lastName = "";
    for (const provider of dnsCatalog) {
      if (provider.name !== lastName) { catalogLines.push("", "# " + provider.name); lastName = provider.name; }
      const selected = provider.selected === true || (provider.selected == null && state.selected_provider_ids?.includes(provider.id));
      catalogLines.push((provider.eligible === true && selected ? "" : "# ") + provider.url);
    }
    if (!dnsCatalogDirty) $("dnsCatalogText").value = catalogLines.join("\n");
    const eligible = dnsCatalog.filter(provider => provider.eligible === true).length;
    text("dnsCatalogInfo", `${dnsCatalog.length} адресов в каталоге, ${eligible} поддерживаемых IP DoH. Редактирование выбора сохраняется после проверки; неизвестные строки и несовместимые протоколы отклоняются.`);
    $("dnsAutoSelect").checked = state.auto_selection_enabled !== false;
    $("dnsOnButton").disabled = false;
    text("dnsOnButton", state.managed ? "Перепроверить и обновить DNS auto" : "Проверить и включить DNS auto");
    $("dnsOffButton").disabled = !state.managed;
  }
  function selectedDNSProviders() {
    const catalog = new Map(dnsCatalog.map(provider => [provider.url, provider]));
    const selected = [];
    const seen = new Set();
    const lines = $("dnsCatalogText").value.split(/\r?\n/);
    if (lines.length > 128 || $("dnsCatalogText").value.length > 16384) throw new Error("Список DNS слишком длинный (максимум 128 строк и 16 КБ).");
    for (let index = 0; index < lines.length; index++) {
      const address = lines[index].trim();
      if (!address || address.startsWith("#")) continue;
      const provider = catalog.get(address);
      if (!provider) throw new Error(`Строка ${index + 1}: неизвестный адрес «${address}». Разрешены только адреса из каталога.`);
      if (provider.eligible !== true) throw new Error(`Строка ${index + 1}: ${address} — ${provider.reason || "не поддерживается DNS auto"}.`);
      if (seen.has(provider.id)) throw new Error(`Строка ${index + 1}: ${address} указан дважды.`);
      seen.add(provider.id);
      selected.push(provider.id);
    }
    return selected;
  }
  function startDNSAction(action) {
    let providers;
    try { providers = selectedDNSProviders(); }
    catch (error) { showBanner("Список DNS", error.message, "failed"); return; }
    if (!providers.length) { showBanner("Провайдеры DNS", "Выберите хотя бы один DNS-сервер.", "failed"); return; }
    if (action === "dns-on" && providers.length < 2) { showBanner("Провайдеры DNS", "Для DNS auto выберите хотя бы два сервера. Оба должны ответить при проверке.", "failed"); return; }
    startAction(action, "", { providers, auto_select: !!$("dnsAutoSelect").checked });
  }
  async function refreshDNS() {
    if (dnsRefreshing) return;
    dnsRefreshing = true;
    try { renderDNS(await api("/api/dns")); }
    catch (error) { showBanner("Состояние DNS", error.message, "failed"); }
    finally { dnsRefreshing = false; }
  }
  function renderJobResult(job) {
    const result = job.result;
    if (!result) return;
    let lines = [];
    if (job.action === "dns-test" || job.action === "dns-on") {
      const probes = Array.isArray(result) ? result : result.probes || [];
      lines = probes.map(p => `${p.name}: ${p.success ? "доступен" : "ошибка"}${p.median_ms != null ? ` · ${Math.round(p.median_ms)} мс` : ""} · ${p.responses}/3 ответов${p.note ? ` · ${p.note}` : ""}`);
      if (job.action === "dns-on" && result.config_file) lines.push("Записан файл: " + result.config_file);
      if (job.action === "dns-on" && result.selected_providers?.length) lines.push("Выбраны: " + result.selected_providers.join(", "));
    } else if (job.action === "dns-verify") {
      lines = ["Файл: " + (result.config_file || "—"), "Прямой маршрут: " + (result.direct?.success ? "DNS ответил" : result.direct?.reason || "нет ответа"), "Выбранный VLESS: " + (result.selected_vless?.success ? "DNS ответил" : result.selected_vless?.reason || "не проверен"), result.scope || ""];
    } else if (job.action === "doctor-network") {
      lines = (result.checks || []).map(c => `${c.ok ? "✓" : "!"} ${c.name}: ${c.detail}${c.action ? ` · ${c.action}` : ""}`);
    } else if (job.action === "doctor") {
      lines = Object.entries(result.checks || {}).map(([name, ok]) => `${ok ? "✓" : "!"} ${name}`);
    } else if (job.action === "startup-check") {
      const format = (title, check) => `${check?.ok ? "✓" : "!"} ${title}: ${(check?.lines || []).join(" · ") || "нет вывода"}`;
      lines = [format("Xray -xtest", result.config_test), format("XKeen PBR", result.pbr_status), format("Entware proxy", result.proxy_status), `Метка генерируемых VLESS: ${result.outbound_mark || "не задана"}`];
      if (!result.config_test?.ok) lines.push("Конфигурация Xray не прошла проверку.");
      lines.push("Успех -xtest не проверяет strict PBR и не доказывает запуск Xray.");
    } else if (job.action === "lan-repair") {
      const path = (status, key) => status?.[key]?.known ? status[key].present ? "правило найдено" : "правило отсутствует" : "проверка недоступна";
      lines = [
        `Результат: ${result.recovered ? "правила восстановлены" : "перехват не подтверждён"}`,
        `Способ: ${result.mode === "netfilter_hook" ? "хук XKeen" : result.mode === "xkeen_start_existing_xray" ? "повторная генерация XKeen" : result.mode === "already_present" ? "правила уже были" : "не запускалось"}`,
        `Основной Xray PID: ${result.main_xray_pid || "не определён"}`,
        `IPv4 TCP: ${path(result.before, "tcp")} → ${path(result.after, "tcp")}`,
        `IPv4 UDP: ${path(result.before, "udp")} → ${path(result.after, "udp")}`,
        `IPv6 TCP: ${path(result.before, "tcp_ipv6")} → ${path(result.after, "tcp_ipv6")}`,
        `IPv6 UDP: ${path(result.before, "udp_ipv6")} → ${path(result.after, "udp_ipv6")}`
      ];
      if (result.command_output?.length) lines.push("Вывод XKeen:", ...result.command_output.slice(-12));
      if (result.syslog_before?.length) lines.push("Системный журнал до действия:", ...result.syslog_before.slice(-8));
      if (result.syslog_after?.length) lines.push("Последние сообщения netfilter:", ...result.syslog_after.slice(-8));
      if (!result.recovered) lines.push("Соберите новый отчёт на вкладке «Статусы» для точной причины.");
    } else if (job.action === "plan") {
      lines = [`Поддерживаемых ключей: ${result.supported_nodes ?? 0}`, `Новых или изменённых: ${result.new_or_changed ?? 0}`, `Не-VLESS записей пропущено: ${result.ignored_non_vless ?? 0}`, `Конфигурация изменится: ${result.configuration_changed ? "да" : "нет"}`];
    } else if (job.action === "keys-check") {
      lines = (result.Keys || []).map(k => `${k.Active ? "●" : "○"} ${k.Name || k.Tag}: ${k.PingMS == null ? "нет ответа" : Math.round(k.PingMS) + " мс"}`);
      if (result.APIWarning) lines.unshift(result.APIWarning);
    }
    if (lines.length) {
      const id = job.action.startsWith("dns-") ? "dnsResult" : "systemResult";
      text(id, lines.join("\n"));
      $(id).hidden = false;
    }
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
      $("autoUpdateButton").disabled = !!state.enabled && state.mode === "auto";
      $("pauseUpdateButton").disabled = !state.enabled;
      text("updateAdvancedState", (!state.enabled ? "Обновления отключены" : state.paused ? "Установка приостановлена" : "Установка разрешена") + (state.pinned_version ? " · закреплена " + state.pinned_version : " · версия не закреплена"));
      $("pauseInstallButton").disabled = !state.enabled || !!state.paused;
      $("resumeInstallButton").disabled = !state.paused;
      $("downloadUpdateButton").disabled = !state.enabled || state.state_invalid;
      $("unpinUpdateButton").disabled = !state.pinned_version;
      $("installUpdateButton").disabled = !state.enabled || !!state.paused || !state.verified || !state.available || !!state.pending_phase || state.state_invalid;
      $("checkUpdateButton").disabled = !state.enabled || state.state_invalid;
    } catch (error) { showBanner("Обновления", error.message, "failed"); }
  }
  async function startAction(action, tag = "", extra = {}) {
    const names = { sync: "Синхронизация", "check-key": "Проверка ключа", "url-test": "URL Test", select: "Выбор ключа", pin: "Закрепление ключа", auto: "Автовыбор", "forget-emergency": "Аварийный ключ", "lan-repair": "Восстановление правил XKeen", "update-enable": "Включение обновлений", "update-check": "Проверка обновлений", "update-install": "Установка обновления", "update-auto": "Автоустановка обновлений", "update-disable": "Отключение обновлений", "update-pause-on": "Пауза установки", "update-pause-off": "Возобновление установки", "update-download": "Загрузка пакета", "update-retry": "Повторная попытка", "dns-test": "Проверка DoH", "dns-verify": "Проверка DNS-маршрутов", "dns-on": "Включение DNS auto", "dns-off": "Откат DNS auto", doctor: "Проверка готовности", "startup-check": "Проверка условий запуска XKeen", "doctor-network": "Диагностика сети", plan: "План подписки", "keys-check": "Проверка ключей", adopt: "Первое подключение", reconcile: "Согласование Xray", gc: "Очистка ключей", recover: "Завершение операции", abort: "Откат операции", "hold-on": "Пауза синхронизации", "hold-off": "Возобновление синхронизации", "url-migrate": "Перенос адреса подписки" };
    try {
      const job = await api("/api/action", { method: "POST", body: JSON.stringify({ action, tag, ...extra }) });
      activeJob = job.id;
      webJob = { action, state: "running", message: "Ожидает завершения" };
      if (currentActivity) renderActivity(currentActivity);
      refreshActivity();
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
      if (["queued", "waiting", "running"].includes(job.state)) {
        webJob = job;
        if (currentActivity) renderActivity(currentActivity);
        showBanner(job.action === "url-test" ? "URL Test" : job.state === "running" ? "Операция выполняется" : "Операция ожидает", job.message);
        if (job.action === "url-test" && job.report?.results?.length) { liveReport = job.report; renderResults(liveReport, true); }
        setTimeout(pollJob, 1200);
        return;
      }
      activeJob = 0;
      webJob = null;
      if (currentActivity) renderActivity(currentActivity);
      liveReport = null;
      showBanner(job.state === "succeeded" ? "Операция завершена" : "Операция не выполнена", job.message, job.state);
      if (job.report?.results?.length) renderResults(job.report);
      renderJobResult(job);
      await refresh();
      await refreshActivity();
      if (job.action === "lan-repair") await refreshSystem();
      if (job.state === "succeeded" && (job.action === "dns-test" || job.action === "dns-on")) dnsCatalogDirty = false;
      if (activePage() === "dns" || job.action.startsWith("dns-")) await refreshDNS();
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
      webJob = { action: "emergency", state: "running", message: "Ожидает завершения" };
      if (currentActivity) renderActivity(currentActivity);
      refreshActivity();
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
  async function saveProbeMode() {
    const checkbox = $("economyChecks");
    const enabled = checkbox.checked;
    checkbox.disabled = true;
    try {
      await api("/api/probe-mode", { method: "PUT", body: JSON.stringify({ economy_checks: enabled }) });
      showBanner("Режим проверки", enabled ? "Экономная проверка включена." : "Проверка отдельным Xray включена.", "succeeded");
      await refresh();
    } catch (error) {
      checkbox.checked = !enabled;
      showBanner("Режим проверки", error.message, "failed");
    } finally { checkbox.disabled = current?.live_probes_allowed !== true; }
  }
  async function pinUpdate(version) {
    try {
      await api("/api/update/pin", { method: "PUT", body: JSON.stringify({ version }) });
      $("pinnedVersion").value = "";
      showBanner("Версия обновления", version ? "Закреплена версия " + version : "Ограничение версии снято", "succeeded");
      await refreshUpdate();
    } catch (error) { showBanner("Версия обновления", error.message, "failed"); }
  }
  async function saveSubscriptionURL() {
    const input = $("subscriptionURL");
    if (!input.value.trim()) { showBanner("Адрес подписки", "Введите HTTPS URL подписки.", "failed"); return; }
    try {
      await api("/api/subscription-url", { method: "PUT", body: JSON.stringify({ url: input.value.trim() }) });
      input.value = "";
      showBanner("Адрес подписки", "Сохранён. Следующая синхронизация использует новый адрес.", "succeeded");
    } catch (error) { showBanner("Адрес подписки", error.message, "failed"); }
  }
  async function changeToken() {
    try {
      await api("/api/token", { method: "PUT", body: JSON.stringify({ current: $("currentToken").value, new: $("newToken").value }) });
      $("currentToken").value = "";
      $("newToken").value = "";
      csrf = "";
      showLogin("Токен изменён. Войдите с новым токеном.");
    } catch (error) { showBanner("Токен WebUI", error.message, "failed"); }
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
  $("economyChecks").addEventListener("change", saveProbeMode);
  $("downloadReportButton").addEventListener("click", downloadReport);
  $("generateStatusReportButton").addEventListener("click", generateStatusReport);
  $("downloadStatusTextButton").addEventListener("click", () => downloadStatusReport("txt"));
  $("downloadStatusJSONButton").addEventListener("click", () => downloadStatusReport("json"));
  $("pinSelectedButton").addEventListener("click", () => { const key = inventoryKeys(current?.keys).find((item) => item.Selected); if (key) startAction("pin", key.Tag); });
  $("autoButton").addEventListener("click", () => startAction("auto"));
  $("emergencyButton").addEventListener("click", startEmergency);
  $("forgetEmergencyButton").addEventListener("click", () => startAction("forget-emergency"));
  $("refreshSystemButton").addEventListener("click", () => { refreshSystem(); refreshActivity(); });
  $("repairLANButton").addEventListener("click", () => {
    if (window.confirm("XKeen пересоздаст правила перехвата LAN. Это может кратко прервать соединения. Продолжить?")) startAction("lan-repair");
  });
  $("stopActivityButton").addEventListener("click", () => controlActivity("/api/activity/stop", "Пауза фоновых задач"));
  $("resumeActivityButton").addEventListener("click", () => controlActivity("/api/activity/resume", "Возобновление фоновых задач"));
	$("refreshDNSButton").addEventListener("click", refreshDNS);
  $("dnsCatalogText").addEventListener("input", () => { dnsCatalogDirty = true; });
  $("dnsOnButton").addEventListener("click", () => startDNSAction("dns-on"));
  $("dnsTestButton").addEventListener("click", () => startDNSAction("dns-test"));
for (const [id, action] of Object.entries({ dnsOffButton: "dns-off", dnsVerifyButton: "dns-verify", doctorButton: "doctor", startupCheckButton: "startup-check", doctorNetworkButton: "doctor-network", planButton: "plan", keysCheckButton: "keys-check", adoptButton: "adopt", reconcileButton: "reconcile", gcButton: "gc", recoverButton: "recover", abortButton: "abort", holdOnButton: "hold-on", holdOffButton: "hold-off", migrateSubscriptionButton: "url-migrate", autoUpdateButton: "update-auto", pauseUpdateButton: "update-disable", pauseInstallButton: "update-pause-on", resumeInstallButton: "update-pause-off", downloadUpdateButton: "update-download", retryUpdateButton: "update-retry" })) {
	  $(id).addEventListener("click", () => startAction(action));
	}
	$("pinUpdateButton").addEventListener("click", () => { const version = $("pinnedVersion").value.trim(); if (version) pinUpdate(version); else showBanner("Версия обновления", "Введите номер версии.", "failed"); });
	$("unpinUpdateButton").addEventListener("click", () => pinUpdate(""));
	$("saveSubscriptionButton").addEventListener("click", saveSubscriptionURL);
	$("changeTokenButton").addEventListener("click", changeToken);
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
        if (["queued", "waiting", "running"].includes(job.state)) { activeJob = job.id; webJob = job; if (currentActivity) renderActivity(currentActivity); showBanner("Операция выполняется", job.message); pollJob(); }
        else renderJobResult(job);
      } else showLogin();
    } catch (error) { showLogin(error.message); }
  })();
  // These endpoints read cached health. Editing sites or running a job must not
  // freeze the global indicators; renderSites already preserves unsaved input.
  setInterval(() => { if (csrf && !document.hidden) { refresh(); refreshActivity(); if (activePage() === "updates" && !activeJob) refreshUpdate(); } }, 5000);
})();
