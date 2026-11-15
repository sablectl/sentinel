import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), "../..");

function contrastRatio(foreground: string, background: string): number {
  const luminance = (colour: string): number => {
    const components = [1, 3, 5].map((index) => {
      const channel = Number.parseInt(colour.slice(index, index + 2), 16) / 255;
      return channel <= 0.04045
        ? channel / 12.92
        : ((channel + 0.055) / 1.055) ** 2.4;
    });
    const red = components[0] ?? 0;
    const green = components[1] ?? 0;
    const blue = components[2] ?? 0;
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
  };
  const high = luminance(foreground);
  const low = luminance(background);
  return (Math.max(high, low) + 0.05) / (Math.min(high, low) + 0.05);
}

describe("dashboard accessibility baseline", () => {
  it("provides a skip link, semantic landmarks and a labelled login form", async () => {
    const html = await readFile(
      join(projectRoot, "src/web/index.html"),
      "utf8",
    );
    expect(html).toContain('href="#main-content"');
    expect(html).toContain(
      '<nav class="navigation" aria-label="Primary navigation">',
    );
    expect(html).toContain('<main id="main-content"');
    expect(html).toContain('for="login-token"');
    expect(html).toContain('aria-live="polite"');
  });

  it("has visible focus, mobile layouts and reduced-motion handling", async () => {
    const styles = await readFile(
      join(projectRoot, "src/web/styles.css"),
      "utf8",
    );
    expect(styles).toContain(":focus-visible");
    expect(styles).toContain("@media (max-width: 600px)");
    expect(styles).toContain("@media (prefers-reduced-motion: reduce)");
  });

  it("keeps greyscale text colours above WCAG AA contrast on black", async () => {
    const styles = await readFile(
      join(projectRoot, "src/web/styles.css"),
      "utf8",
    );
    const background = /--background:\s*(#[0-9a-fA-F]{6})/.exec(styles)?.[1];
    const foreground = /--foreground:\s*(#[0-9a-fA-F]{6})/.exec(styles)?.[1];
    const muted = /--muted:\s*(#[0-9a-fA-F]{6})/.exec(styles)?.[1];
    const subtle = /--subtle:\s*(#[0-9a-fA-F]{6})/.exec(styles)?.[1];
    expect(background).toBeDefined();
    expect(foreground).toBeDefined();
    expect(muted).toBeDefined();
    expect(subtle).toBeDefined();
    if (
      background === undefined ||
      foreground === undefined ||
      muted === undefined ||
      subtle === undefined
    ) {
      throw new Error("dashboard palette tokens are missing");
    }
    expect(contrastRatio(foreground, background)).toBeGreaterThanOrEqual(4.5);
    expect(contrastRatio(muted, background)).toBeGreaterThanOrEqual(4.5);
    expect(contrastRatio(subtle, background)).toBeGreaterThanOrEqual(4.5);
  });
});
