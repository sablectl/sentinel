export type Child = Node | string | number | null | undefined | false;
export type Attributes = Readonly<Record<string, string | boolean | undefined>>;

let counter = 0;

export function uniqueId(prefix: string): string {
  counter += 1;
  return `${prefix}-${counter}`;
}

function append(node: Element, children: readonly Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(
      typeof child === "object"
        ? child
        : document.createTextNode(String(child)),
    );
  }
}

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attributes: Attributes = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) {
    if (value === undefined || value === false) continue;
    if (name === "className") node.className = String(value);
    else if (name === "textContent") node.textContent = String(value);
    else node.setAttribute(name, value === true ? "" : value);
  }
  append(node, children);
  return node;
}

export function replaceChildren(parent: Element, ...children: Child[]): void {
  const nodes: Node[] = [];
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    nodes.push(
      typeof child === "object"
        ? child
        : document.createTextNode(String(child)),
    );
  }
  parent.replaceChildren(...nodes);
}

export function button(
  label: string,
  action: () => void,
  attributes: Attributes = {},
): HTMLButtonElement {
  const result = el("button", { type: "button", ...attributes }, label);
  result.addEventListener("click", action);
  return result;
}

export function labelledField(
  label: string,
  input: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
): HTMLLabelElement {
  const container = el(
    "label",
    { className: "field" },
    el("span", {}, label),
    input,
  );
  return container;
}
