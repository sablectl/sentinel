const ESCAPE = String.fromCharCode(0x1b);
const BELL = String.fromCharCode(0x07);
const ANSI_SEQUENCE = new RegExp(
  `${ESCAPE}(?:\\[[0-?]*[ -/]*[@-~]|\\][^${BELL}]*(?:${BELL}|${ESCAPE}\\\\))`,
  "g",
);
const CONTROL_CHARACTERS = /\p{Cc}/gu;

export function sanitiseMessage(value: string): string {
  return value
    .replace(ANSI_SEQUENCE, "")
    .replace(CONTROL_CHARACTERS, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function escapeOriginal(value: string): string {
  return JSON.stringify(value);
}
