import { el } from "../dom.js";

export function noteEditor(
  submit: (note: string) => Promise<void>,
): HTMLFormElement {
  const textarea = el("textarea", {
    name: "note",
    rows: "4",
    maxlength: "4000",
    required: true,
  });
  const status = el("p", { role: "status", className: "form-status" });
  const form = el(
    "form",
    { className: "note-editor" },
    el(
      "label",
      { className: "field" },
      el("span", {}, "Investigation note"),
      textarea,
    ),
    el("button", { type: "submit", className: "button" }, "Save note"),
    status,
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const value = textarea.value;
    if (value.trim().length === 0) {
      status.textContent = "Enter a note before saving.";
      return;
    }
    void submit(value)
      .then(() => {
        textarea.value = "";
        status.textContent = "Note saved.";
      })
      .catch((error: unknown) => {
        status.textContent =
          error instanceof Error ? error.message : "Note could not be saved.";
      });
  });
  return form;
}
