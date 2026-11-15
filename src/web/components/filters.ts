import { el } from "../dom.js";

export interface FilterValue {
  readonly name: string;
  readonly label: string;
  readonly value: string;
  readonly type?: "text" | "date" | "number";
  readonly options?: readonly {
    readonly value: string;
    readonly label: string;
  }[];
}

export function filterBar(
  fields: readonly FilterValue[],
  submit: (values: Readonly<Record<string, string>>) => void,
): HTMLElement {
  const controls = new Map<string, HTMLInputElement | HTMLSelectElement>();
  const form = el(
    "form",
    { className: "filter-bar", role: "search" },
    ...fields.map((field) => {
      const control =
        field.options === undefined
          ? el("input", {
              type: field.type ?? "text",
              name: field.name,
              value: field.value,
              autocomplete: "off",
            })
          : el(
              "select",
              { name: field.name },
              ...field.options.map((option) =>
                el("option", { value: option.value }, option.label),
              ),
            );
      control.value = field.value;
      controls.set(field.name, control);
      return el(
        "label",
        { className: "field" },
        el("span", {}, field.label),
        control,
      );
    }),
    el("button", { type: "submit", className: "button" }, "Apply filters"),
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const values: Record<string, string> = {};
    for (const [name, control] of controls) values[name] = control.value;
    submit(values);
  });
  return form;
}
