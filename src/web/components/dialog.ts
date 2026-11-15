import { el } from "../dom.js";

export function dialog(title: string, content: Node): HTMLDialogElement {
  const element = el(
    "dialog",
    { className: "dialog", "aria-label": title },
    el(
      "header",
      {},
      el("h2", {}, title),
      el(
        "button",
        {
          type: "button",
          className: "button button-secondary",
          "data-close": "true",
        },
        "Close",
      ),
    ),
    content,
  );
  element.addEventListener("click", (event) => {
    if (event.target === element) element.close();
  });
  element
    .querySelector<HTMLButtonElement>("[data-close]")
    ?.addEventListener("click", () => {
      element.close();
    });
  return element;
}
