import { api, ApiError, describeError } from "./api.js";
import { el, replaceChildren } from "./dom.js";
import { state, stateEvents, updateState } from "./store.js";
import { startStream } from "./stream.js";
import type { View } from "./views/shared.js";
import { alertsView } from "./views/alerts.js";
import { detectionsView } from "./views/detections.js";
import { eventsView } from "./views/events.js";
import { investigationsView } from "./views/investigations.js";
import { overviewView } from "./views/overview.js";
import { sourcesView } from "./views/sources.js";
import { systemView } from "./views/system.js";

const ROUTES: readonly {
  readonly id: string;
  readonly title: string;
  readonly create: () => View;
}[] = [
  { id: "overview", title: "Overview", create: overviewView },
  { id: "events", title: "Events", create: eventsView },
  { id: "detections", title: "Detections", create: detectionsView },
  { id: "alerts", title: "Alerts", create: alertsView },
  { id: "investigations", title: "Investigations", create: investigationsView },
  { id: "sources", title: "Sources", create: sourcesView },
  { id: "system", title: "System", create: systemView },
];

function required(id: string): HTMLElement {
  const element = document.getElementById(id);
  if (element === null) throw new Error(`dashboard element '${id}' is missing`);
  return element;
}

function requiredInput(id: string): HTMLInputElement {
  const element = document.getElementById(id);
  if (!(element instanceof HTMLInputElement)) {
    throw new Error(`dashboard input '${id}' is missing`);
  }
  return element;
}

function requiredForm(id: string): HTMLFormElement {
  const element = document.getElementById(id);
  if (!(element instanceof HTMLFormElement)) {
    throw new Error(`dashboard form '${id}' is missing`);
  }
  return element;
}

function requiredList(id: string): HTMLUListElement {
  const element = document.getElementById(id);
  if (!(element instanceof HTMLUListElement)) {
    throw new Error(`dashboard list '${id}' is missing`);
  }
  return element;
}

function requiredButton(id: string): HTMLButtonElement {
  const element = document.getElementById(id);
  if (!(element instanceof HTMLButtonElement)) {
    throw new Error(`dashboard button '${id}' is missing`);
  }
  return element;
}

const loginPanel = required("login-panel");
const loginForm = requiredForm("login-form");
const loginToken = requiredInput("login-token");
const loginStatus = required("login-status");
const appShell = required("app-shell");
const navList = requiredList("nav-list");
const viewRoot = required("view-root");
const connection = required("connection");
const connectionText = required("connection-text");
const degradedBanner = required("degraded-banner");
const footerVersion = required("footer-version");
const logoutButton = requiredButton("logout");

let currentView: View | undefined;
let stopStream: (() => void) | undefined;
let loginPending = false;

function renderNavigation(activeId: string): void {
  replaceChildren(
    navList,
    ...ROUTES.map((route) => {
      const link = el(
        "a",
        {
          href: `#/${route.id}`,
          ...(route.id === activeId ? { "aria-current": "page" } : {}),
        },
        route.title,
      );
      return el("li", {}, link);
    }),
  );
}

function routeId(): string {
  const value = window.location.hash.replace(/^#\/?/, "").split("?", 1)[0];
  return ROUTES.some((route) => route.id === value)
    ? (value ?? "overview")
    : "overview";
}

function renderView(): void {
  if (!state.authenticated) return;
  const id = routeId();
  const route = ROUTES.find((candidate) => candidate.id === id) ?? ROUTES[0];
  if (route === undefined) return;
  currentView?.dispose();
  currentView = route.create();
  replaceChildren(viewRoot, currentView.root);
  renderNavigation(route.id);
  updateState({ currentView: route.id });
  viewRoot.querySelector<HTMLElement>("h1")?.focus({ preventScroll: true });
}

function updateConnection(): void {
  connection.dataset["state"] = state.connection;
  const labels = {
    connecting: "Connecting",
    live: "Live",
    reconnecting: "Reconnecting",
    offline: "Offline",
  } as const;
  connectionText.textContent = labels[state.connection];
  degradedBanner.hidden = state.degraded === 0;
  degradedBanner.textContent =
    state.degraded === 0
      ? ""
      : `Live updates are being dropped (${state.degraded} or more). The dashboard remains usable; refresh to load current data.`;
}

function showLogin(message = ""): void {
  currentView?.dispose();
  currentView = undefined;
  stopStream?.();
  stopStream = undefined;
  updateState({ authenticated: false, connection: "offline" });
  appShell.hidden = true;
  loginPanel.hidden = false;
  loginToken.value = "";
  loginStatus.textContent = message;
  loginToken.focus();
}

function showDashboard(): void {
  loginPanel.hidden = true;
  appShell.hidden = false;
  updateState({ authenticated: true, connection: "connecting", degraded: 0 });
  renderView();
  stopStream?.();
  stopStream = startStream();
  void api
    .system()
    .then((system) => {
      footerVersion.textContent = `Version ${system.version}`;
    })
    .catch(() => {
      footerVersion.textContent = "";
    });
}

loginForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (loginPending) return;
  const token = loginToken.value.trim();
  loginToken.value = "";
  if (token.length === 0) {
    loginStatus.textContent =
      "Enter the access token from the local protected file.";
    return;
  }
  loginPending = true;
  loginStatus.textContent = "Establishing a local session…";
  const submit = loginForm.querySelector<HTMLButtonElement>(
    'button[type="submit"]',
  );
  if (submit !== null) submit.disabled = true;
  void api
    .login(token)
    .then(() => {
      loginStatus.textContent = "";
      showDashboard();
    })
    .catch((error: unknown) => {
      loginStatus.textContent = describeError(error);
      loginToken.focus();
    })
    .finally(() => {
      loginPending = false;
      if (submit !== null) submit.disabled = false;
    });
});

logoutButton.addEventListener("click", () => {
  logoutButton.disabled = true;
  void api
    .logout()
    .catch(() => undefined)
    .finally(() => {
      logoutButton.disabled = false;
      showLogin("Session closed. Enter the local access token to continue.");
    });
});

window.addEventListener("hashchange", renderView);
window.addEventListener("sentinel-session-expired", () => {
  showLogin("The local session expired. Enter the access token to continue.");
});
window.addEventListener("beforeunload", () => {
  currentView?.dispose();
  stopStream?.();
});
stateEvents.on(updateConnection);

if (window.location.hash.startsWith("#session=")) {
  window.history.replaceState(
    null,
    "",
    `${window.location.pathname}${window.location.search}`,
  );
}

void api
  .session()
  .then((session) => {
    if (session.authenticated) showDashboard();
    else showLogin();
  })
  .catch((error: unknown) => {
    showLogin(
      error instanceof ApiError && error.status === 401
        ? ""
        : describeError(error),
    );
  });
