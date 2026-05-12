// ── SHA-256 via Web Crypto API ────────────────────────────────────────────
async function sha256(message) {
  const data = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── HTML escaping (XSS prevention) ───────────────────────────────────────
function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ── PII masking ───────────────────────────────────────────────────────────
function maskCpf(cpf) {
  if (!cpf) return "—";
  return String(cpf).replace(/^(\d{3})\.(\d{3})\.(\d{3}-\d{2})$/, "$1.***.***-**");
}

function maskEmail(email) {
  if (!email) return "—";
  const [local, domain] = String(email).split("@");
  if (!domain) return "***@***";
  return local.slice(0, 2).padEnd(local.length, "*") + "@" + domain;
}

function maskPhone(phone) {
  if (!phone) return "—";
  return String(phone).replace(/(\(\d{2}\)\s*)\d{4,5}(-\d{4})/, "$1*****$2");
}

// ── Users (passwords stored as SHA-256 hashes — no plaintext) ────────────
// Demo credentials (announced in class):
//   aluno@faculdade.local     → senha: 123456
//   professor@faculdade.local → senha: 123456
//   admin@faculdade.local     → senha: admin
const USERS = [
  {
    id: 1,
    name: "Ana Souza",
    email: "aluno@faculdade.local",
    passwordHash: "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
    role: "ALUNO",
    studentId: "202400001"
  },
  {
    id: 2,
    name: "Prof. Carlos Lima",
    email: "professor@faculdade.local",
    passwordHash: "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
    role: "PROFESSOR",
    classes: ["5A", "5B"]
  },
  {
    id: 3,
    name: "Administrador Geral",
    email: "admin@faculdade.local",
    passwordHash: "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
    role: "ADMIN"
  }
];

// ── Role-based permissions ────────────────────────────────────────────────
const PERMISSIONS = {
  ADMIN:     ["view_all", "view_full_pii", "view_internal_notes",
               "create", "edit_status", "delete",
               "export", "clear_logs", "reset", "change_role"],
  PROFESSOR: ["view_all", "view_masked_pii", "view_internal_notes",
               "create", "edit_status"],
  ALUNO:     ["view_own", "view_masked_pii"]
};

function can(action) {
  const session = getSession();
  if (!session) return false;
  return (PERMISSIONS[session.role] || []).includes(action);
}

// ── Storage keys ──────────────────────────────────────────────────────────
const STORAGE_KEYS = {
  session:     "ocorrencias_sessao",
  occurrences: "ocorrencias_registros",
  audit:       "ocorrencias_logs"
};

// ── Login brute-force throttle (in-memory) ────────────────────────────────
const loginAttempts = { count: 0, lockedUntil: null };

// ── Initial demo data ─────────────────────────────────────────────────────
const INITIAL_OCCURRENCES = [
  {
    id: "OC-1001",
    studentName: "Marina Alves",
    studentId: "202300145",
    studentCpf: "123.456.789-10",
    studentEmail: "marina.alves@email.local",
    studentPhone: "(47) 99999-1010",
    category: "Nota",
    priority: "Média",
    description: "Solicitação de revisão de nota da avaliação bimestral.",
    internalNote: "Verificar com a coordenação antes de responder.",
    status: "Aberta",
    createdBy: "professor@faculdade.local",
    createdAt: "2026-05-05T18:40:00.000Z"
  },
  {
    id: "OC-1002",
    studentName: "Rafael Martins",
    studentId: "202200771",
    studentCpf: "987.654.321-00",
    studentEmail: "rafael.martins@email.local",
    studentPhone: "(47) 98888-2020",
    category: "Frequência",
    priority: "Alta",
    description: "Aluno contesta lançamento de falta em aula prática.",
    internalNote: "Conferir chamada manual.",
    status: "Em análise",
    createdBy: "professor@faculdade.local",
    createdAt: "2026-05-05T18:50:00.000Z"
  },
  {
    id: "OC-1003",
    studentName: "Beatriz Costa",
    studentId: "202100441",
    studentCpf: "111.222.333-44",
    studentEmail: "beatriz.costa@email.local",
    studentPhone: "(47) 97777-3030",
    category: "Solicitação administrativa",
    priority: "Crítica",
    description: "Solicitação envolvendo documentação acadêmica e prazo de matrícula.",
    internalNote: "Priorizar atendimento.",
    status: "Aberta",
    createdBy: "admin@faculdade.local",
    createdAt: "2026-05-05T19:00:00.000Z"
  },
  {
    id: "OC-1004",
    studentName: "Ana Souza",
    studentId: "202400001",
    studentCpf: "222.333.444-55",
    studentEmail: "aluno@faculdade.local",
    studentPhone: "(47) 99999-4040",
    category: "Nota",
    priority: "Baixa",
    description: "Consulta sobre prazo para revisão de prova do segundo bimestre.",
    internalNote: "Aluna tem bom histórico acadêmico. Verificar procedimento padrão.",
    status: "Aberta",
    createdBy: "professor@faculdade.local",
    createdAt: "2026-05-05T19:30:00.000Z"
  }
];

// ── DOM refs ──────────────────────────────────────────────────────────────
const loginView            = document.querySelector("#loginView");
const appView              = document.querySelector("#appView");
const loginForm            = document.querySelector("#loginForm");
const loginError           = document.querySelector("#loginError");
const occurrenceForm       = document.querySelector("#occurrenceForm");
const formError            = document.querySelector("#formError");
const logoutBtn            = document.querySelector("#logoutBtn");
const exportBtn            = document.querySelector("#exportBtn");
const clearLogsBtn         = document.querySelector("#clearLogsBtn");
const resetBtn             = document.querySelector("#resetBtn");
const searchInput          = document.querySelector("#search");
const roleSelect           = document.querySelector("#roleSelect");
const sessionBadge         = document.querySelector("#sessionBadge");
const currentUserName      = document.querySelector("#currentUserName");
const currentUserDetails   = document.querySelector("#currentUserDetails");
const occurrencesTable     = document.querySelector("#occurrencesTable");
const auditLog             = document.querySelector("#auditLog");
const auditSection         = document.querySelector("#auditSection");
const totalOccurrences     = document.querySelector("#totalOccurrences");
const criticalOccurrences  = document.querySelector("#criticalOccurrences");
const lastUpdate           = document.querySelector("#lastUpdate");
const adminTools           = document.querySelector("#adminTools");
const newOccurrenceSection = document.querySelector("#newOccurrenceSection");
const roleSwitchSection    = document.querySelector("#roleSwitchSection");

// ── Data helpers ──────────────────────────────────────────────────────────
function getOccurrences() {
  return JSON.parse(localStorage.getItem(STORAGE_KEYS.occurrences) || "[]");
}

function saveOccurrences(occurrences) {
  localStorage.setItem(STORAGE_KEYS.occurrences, JSON.stringify(occurrences));
}

function getAuditLogs() {
  return JSON.parse(localStorage.getItem(STORAGE_KEYS.audit) || "[]");
}

function saveAuditLogs(logs) {
  localStorage.setItem(STORAGE_KEYS.audit, JSON.stringify(logs));
}

function getSession() {
  return JSON.parse(localStorage.getItem(STORAGE_KEYS.session) || "null");
}

function saveSession(user) {
  // Strip credential fields before storing — never persist passwords
  const { passwordHash, password, ...safeUser } = user;
  localStorage.setItem(STORAGE_KEYS.session, JSON.stringify(safeUser));
}

// ── Audit logging ─────────────────────────────────────────────────────────
function writeLog(action, detail) {
  const session = getSession();
  const logs = getAuditLogs();

  logs.unshift({
    when:   new Date().toISOString(),
    user:   session ? session.email : "anonimo",
    role:   session ? session.role  : "SEM_SESSAO",
    action,
    detail: String(detail).slice(0, 500)
  });

  saveAuditLogs(logs.slice(0, 500));
}

// ── UI: views ─────────────────────────────────────────────────────────────
function showLogin() {
  loginView.classList.remove("hidden");
  appView.classList.add("hidden");
  logoutBtn.classList.add("hidden");
  sessionBadge.textContent = "Sessão não iniciada";
  sessionBadge.classList.add("muted");
  if (loginError) { loginError.textContent = ""; loginError.classList.add("hidden"); }
}

function showApp(user) {
  loginView.classList.add("hidden");
  appView.classList.remove("hidden");
  logoutBtn.classList.remove("hidden");

  sessionBadge.textContent = `${user.name} — ${user.role}`;
  sessionBadge.classList.remove("muted");

  currentUserName.textContent = user.name;
  currentUserDetails.textContent = `${user.email} | Perfil: ${user.role}`;

  applyRoleUI(user);
  render();
}

function applyRoleUI(user) {
  // Role-switch selector: visible only for ADMIN (to simulate other roles)
  if (roleSwitchSection) {
    roleSwitchSection.classList.toggle("hidden", !can("change_role"));
    if (roleSelect) roleSelect.value = user.role;
  }

  // Occurrence creation form: PROFESSOR and ADMIN only
  if (newOccurrenceSection) {
    newOccurrenceSection.classList.toggle("hidden", !can("create"));
  }

  // Admin tools panel
  if (adminTools) {
    adminTools.classList.toggle("hidden", !can("export") && !can("clear_logs") && !can("reset"));
  }
  if (exportBtn)   exportBtn.classList.toggle("hidden",   !can("export"));
  if (clearLogsBtn) clearLogsBtn.classList.toggle("hidden", !can("clear_logs"));
  if (resetBtn)    resetBtn.classList.toggle("hidden",    !can("reset"));

  // Audit log section: ADMIN only
  if (auditSection) {
    auditSection.classList.toggle("hidden", !can("clear_logs"));
  }
}

// ── Authentication ────────────────────────────────────────────────────────
async function login(email, password) {
  if (loginAttempts.lockedUntil && Date.now() < loginAttempts.lockedUntil) {
    const remaining = Math.ceil((loginAttempts.lockedUntil - Date.now()) / 1000);
    showLoginError(`Acesso temporariamente bloqueado. Aguarde ${remaining} segundo(s).`);
    return;
  }

  const hash = await sha256(password);
  const user = USERS.find(u => u.email === email && u.passwordHash === hash);

  if (!user) {
    loginAttempts.count++;
    writeLog("LOGIN_FALHOU", `Tentativa inválida para ${email}`);

    if (loginAttempts.count >= 5) {
      loginAttempts.lockedUntil = Date.now() + 30_000;
      loginAttempts.count = 0;
      showLoginError("Conta bloqueada por 30 segundos após múltiplas tentativas inválidas.");
    } else {
      const remaining = 5 - loginAttempts.count;
      showLoginError(`Usuário ou senha inválidos. ${remaining} tentativa(s) restante(s).`);
    }
    return;
  }

  loginAttempts.count = 0;
  loginAttempts.lockedUntil = null;

  saveSession(user);
  writeLog("LOGIN_OK", `Usuário ${user.email} autenticou com sucesso.`);
  showApp(user);
}

function showLoginError(msg) {
  if (loginError) {
    loginError.textContent = msg;
    loginError.classList.remove("hidden");
  }
}

function logout() {
  const session = getSession();
  writeLog("LOGOUT", session ? `${session.email} encerrou a sessão.` : "Sessão encerrada.");
  localStorage.removeItem(STORAGE_KEYS.session);
  showLogin();
}

// ── Role change (ADMIN only) ──────────────────────────────────────────────
function changeRole(newRole) {
  if (!can("change_role")) {
    writeLog("ACESSO_NEGADO", "Tentativa de alteração de perfil sem permissão.");
    return;
  }
  const session = getSession();
  if (!session) return;
  session.role = newRole;
  saveSession(session);
  writeLog("PERFIL_ALTERADO", `Perfil de simulação alterado para ${newRole}.`);
  showApp(session);
}

// ── Occurrence form validation ────────────────────────────────────────────
function validateOccurrenceForm(data) {
  const errors = [];

  if (!data.studentName.trim())
    errors.push("Nome do aluno é obrigatório.");

  if (!data.studentId.trim())
    errors.push("Matrícula é obrigatória.");
  else if (!/^\d{7,12}$/.test(data.studentId.trim()))
    errors.push("Matrícula deve conter apenas dígitos (7–12 caracteres).");

  if (data.studentCpf.trim() && !/^\d{3}\.\d{3}\.\d{3}-\d{2}$/.test(data.studentCpf.trim()))
    errors.push("CPF deve estar no formato 000.000.000-00.");

  if (data.studentEmail.trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.studentEmail.trim()))
    errors.push("E-mail inválido.");

  if (!data.description.trim())
    errors.push("Descrição da ocorrência é obrigatória.");

  if (!data.privacyAck)
    errors.push("É necessário confirmar a responsabilidade pelo registro dos dados.");

  return errors;
}

// ── Occurrences CRUD ──────────────────────────────────────────────────────
function createOccurrence(event) {
  event.preventDefault();

  if (!can("create")) {
    writeLog("ACESSO_NEGADO", "Tentativa de criar ocorrência sem permissão.");
    return;
  }

  const data = {
    studentName:  document.querySelector("#studentName").value,
    studentId:    document.querySelector("#studentId").value,
    studentCpf:   document.querySelector("#studentCpf").value,
    studentEmail: document.querySelector("#studentEmail").value,
    studentPhone: document.querySelector("#studentPhone").value,
    category:     document.querySelector("#category").value,
    priority:     document.querySelector("#priority").value,
    description:  document.querySelector("#description").value,
    internalNote: document.querySelector("#internalNote").value,
    privacyAck:   document.querySelector("#privacyAck").checked
  };

  const errors = validateOccurrenceForm(data);
  if (errors.length > 0) {
    if (formError) {
      formError.innerHTML = errors.map(escapeHtml).join("<br>");
      formError.classList.remove("hidden");
    }
    return;
  }
  if (formError) formError.classList.add("hidden");

  const session = getSession();
  const occurrence = {
    id:        `OC-${Date.now().toString().slice(-7)}`,
    ...data,
    status:    "Aberta",
    createdBy: session ? session.email : "desconhecido",
    createdAt: new Date().toISOString()
  };

  const occurrences = getOccurrences();
  occurrences.unshift(occurrence);
  saveOccurrences(occurrences);

  writeLog(
    "OCORRENCIA_CRIADA",
    `Ocorrência ${occurrence.id} criada para ${occurrence.studentName}. Categoria: ${occurrence.category}.`
  );

  occurrenceForm.reset();
  render();
}

function deleteOccurrence(id) {
  if (!can("delete")) {
    writeLog("ACESSO_NEGADO", `Tentativa de excluir ocorrência ${id} sem permissão.`);
    return;
  }
  if (!confirm(`Tem certeza que deseja excluir a ocorrência ${id}?\nEsta ação não pode ser desfeita.`)) {
    return;
  }

  const occurrences = getOccurrences();
  const updated = occurrences.filter(item => item.id !== id);

  saveOccurrences(updated);
  writeLog("OCORRENCIA_EXCLUIDA", `Ocorrência ${id} excluída.`);
  render();
}

function changeStatus(id, status) {
  if (!can("edit_status")) {
    writeLog("ACESSO_NEGADO", `Tentativa de alterar status de ${id} sem permissão.`);
    return;
  }

  const occurrences = getOccurrences();
  const occurrence = occurrences.find(item => item.id === id);
  if (!occurrence) return;

  occurrence.status    = status;
  occurrence.updatedAt = new Date().toISOString();
  occurrence.updatedBy = getSession()?.email || "desconhecido";

  saveOccurrences(occurrences);
  writeLog("STATUS_ALTERADO", `Ocorrência ${id} atualizada para "${status}".`);
  render();
}

// ── Export (ADMIN only, no credentials) ──────────────────────────────────
function exportEverything() {
  if (!can("export")) {
    writeLog("ACESSO_NEGADO", "Tentativa de exportação sem permissão.");
    alert("Acesso restrito. Apenas administradores podem exportar dados.");
    return;
  }

  const session = getSession();
  const payload = {
    exportedAt: new Date().toISOString(),
    exportedBy: session ? { name: session.name, email: session.email, role: session.role } : null,
    occurrences: getOccurrences(),
    audit: getAuditLogs()
    // NOTE: usuários, hashes e tokens NÃO são incluídos na exportação
  };

  const blob   = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url    = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href     = url;
  anchor.download = `backup-ocorrencias-${new Date().toISOString().slice(0, 10)}.json`;
  anchor.click();
  URL.revokeObjectURL(url);

  writeLog("EXPORTACAO", "Administrador exportou os dados do sistema (sem credenciais).");
}

// ── Admin tools ───────────────────────────────────────────────────────────
function clearLogs() {
  if (!can("clear_logs")) {
    writeLog("ACESSO_NEGADO", "Tentativa de limpar logs sem permissão.");
    return;
  }
  if (!confirm("Tem certeza que deseja apagar todos os logs de auditoria?")) return;

  saveAuditLogs([]);
  writeLog("LOGS_LIMPOS", "Logs de auditoria limpos pelo administrador.");
  render();
}

function resetData() {
  if (!can("reset")) {
    writeLog("ACESSO_NEGADO", "Tentativa de restaurar dados sem permissão.");
    return;
  }
  if (!confirm("Tem certeza que deseja restaurar os dados iniciais?\nTodos os registros atuais serão perdidos.")) return;

  localStorage.setItem(STORAGE_KEYS.occurrences, JSON.stringify(INITIAL_OCCURRENCES));
  localStorage.setItem(STORAGE_KEYS.audit,       JSON.stringify([]));
  localStorage.removeItem(STORAGE_KEYS.session);
  boot();
}

// ── Render ────────────────────────────────────────────────────────────────
function render() {
  const session = getSession();
  const term    = searchInput.value.toLowerCase();
  let occurrences = getOccurrences();

  // ALUNO: filter to own occurrences only
  if (session && session.role === "ALUNO") {
    occurrences = occurrences.filter(item =>
      item.studentEmail === session.email ||
      item.studentId    === session.studentId
    );
  }

  const filtered = occurrences.filter(item => {
    const searchable = [
      item.id, item.studentName, item.studentId,
      item.category, item.priority, item.status, item.description
    ].join(" ").toLowerCase();
    return searchable.includes(term);
  });

  totalOccurrences.textContent    = occurrences.length;
  criticalOccurrences.textContent = occurrences.filter(i => i.priority === "Crítica").length;
  lastUpdate.textContent = `Atualizado em ${new Date().toLocaleTimeString("pt-BR")}`;

  const showFullPii      = can("view_full_pii");
  const showInternalNote = can("view_internal_notes");
  const showActions      = can("edit_status") || can("delete");

  occurrencesTable.innerHTML = filtered.map(item => `
    <tr>
      <td>
        <strong>${escapeHtml(item.studentName)}</strong><br />
        <span class="muted-text">${escapeHtml(item.studentId)}</span>
      </td>
      <td>${escapeHtml(showFullPii ? item.studentCpf   : maskCpf(item.studentCpf))}</td>
      <td>
        ${escapeHtml(showFullPii ? item.studentEmail : maskEmail(item.studentEmail))}<br />
        ${escapeHtml(showFullPii ? item.studentPhone : maskPhone(item.studentPhone))}
      </td>
      <td>${escapeHtml(item.category)}</td>
      <td><span class="priority ${escapeHtml(item.priority)}">${escapeHtml(item.priority)}</span></td>
      <td>${escapeHtml(item.status)}</td>
      <td>
        <strong>Descrição:</strong> ${escapeHtml(item.description)}<br />
        ${showInternalNote ? `<strong>Obs. interna:</strong> ${escapeHtml(item.internalNote)}` : ""}
      </td>
      <td>
        <div class="row-actions">
          ${can("edit_status") ? `
            <button class="btn secondary"
              data-action="change-status"
              data-id="${escapeHtml(item.id)}"
              data-status="Em análise">Em análise</button>
            <button class="btn secondary"
              data-action="change-status"
              data-id="${escapeHtml(item.id)}"
              data-status="Resolvida">Resolver</button>
          ` : ""}
          ${can("delete") ? `
            <button class="btn danger"
              data-action="delete"
              data-id="${escapeHtml(item.id)}">Excluir</button>
          ` : ""}
          ${!showActions ? `<span class="muted-text">Somente leitura</span>` : ""}
        </div>
      </td>
    </tr>
  `).join("");

  if (!auditSection) return;

  // Audit log (ADMIN only — already hidden via applyRoleUI, but render defensively)
  if (!can("clear_logs")) return;

  const logs = getAuditLogs();
  if (logs.length === 0) {
    auditLog.innerHTML = `<div class="notice">Nenhum log registrado.</div>`;
  } else {
    auditLog.innerHTML = logs.map(log => `
      <div class="log-item">
        <strong>${escapeHtml(log.when)}</strong><br />
        usuário=${escapeHtml(log.user || "—")} | perfil=${escapeHtml(log.role || "—")} | ação=${escapeHtml(log.action)}<br />
        detalhe=${escapeHtml(log.detail)}
      </div>
    `).join("");
  }
}

// ── Event delegation for table buttons ───────────────────────────────────
occurrencesTable.addEventListener("click", event => {
  const btn = event.target.closest("[data-action]");
  if (!btn) return;
  const action = btn.dataset.action;
  const id     = btn.dataset.id;
  if (action === "change-status") changeStatus(id, btn.dataset.status);
  if (action === "delete")        deleteOccurrence(id);
});

// ── Boot ──────────────────────────────────────────────────────────────────
function boot() {
  if (!localStorage.getItem(STORAGE_KEYS.occurrences)) {
    localStorage.setItem(STORAGE_KEYS.occurrences, JSON.stringify(INITIAL_OCCURRENCES));
  }
  if (!localStorage.getItem(STORAGE_KEYS.audit)) {
    localStorage.setItem(STORAGE_KEYS.audit, JSON.stringify([{
      when:   new Date().toISOString(),
      user:   "sistema",
      action: "BASE_INICIAL_CRIADA",
      detail: "Dados fictícios carregados no localStorage."
    }]));
  }

  const session = getSession();
  if (session) {
    showApp(session);
  } else {
    showLogin();
  }
}

// ── Global event listeners ────────────────────────────────────────────────
loginForm.addEventListener("submit", async event => {
  event.preventDefault();
  await login(
    document.querySelector("#email").value,
    document.querySelector("#password").value
  );
});

occurrenceForm.addEventListener("submit", createOccurrence);
logoutBtn.addEventListener("click", logout);
exportBtn.addEventListener("click", exportEverything);
clearLogsBtn.addEventListener("click", clearLogs);
resetBtn.addEventListener("click", resetData);
searchInput.addEventListener("input", render);
roleSelect.addEventListener("change", event => changeRole(event.target.value));

boot();
