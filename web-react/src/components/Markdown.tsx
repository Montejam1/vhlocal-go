import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Mermaid } from "./Mermaid";

// Feature 015 (C-A9): one link rule. A relative target resolves through the OWNING
// report's confined file endpoint (base) so the portable links a report writes
// (review_units.json, threat_model.md) work in-app; only http(s):/mailto: absolute
// targets and #anchors pass; everything else is rendered as text (no href).
const ALLOWED_SCHEMES = ["http:", "https:", "mailto:"];

export function mdHref(href: string, base?: string): string | null {
  const h = String(href || "").trim();
  if (!h) return null;
  if (h[0] === "#") return h;
  const m = h.match(/^([a-zA-Z][a-zA-Z0-9+.-]*:)/);
  if (m) return ALLOWED_SCHEMES.includes(m[1].toLowerCase()) ? h : null;
  if (h.startsWith("//") || h[0] === "/") return null;
  if (!base) return null;
  const [path, frag] = h.replace(/^\.\//, "").split("#");
  return `${base}?path=${encodeURIComponent(path)}${frag ? `#${frag}` : ""}`;
}

/** Render markdown (threat model / report bodies). A ```mermaid fenced block is
 *  rendered as a live diagram; everything else uses GFM (tables, lists, code).
 *  `base` is the owning report's file endpoint (`/api/reports/<id>/file`). */
export function Markdown({ children, base }: { children: string; base?: string }) {
  return (
    <div className="md max-w-[960px]">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        urlTransform={(url) => mdHref(url, base) ?? ""}
        components={{
          a({ href, children, ...props }) {
            if (!href) return <span>{children}</span>; // disallowed scheme → text
            const external = /^(https?:|mailto:)/i.test(href);
            return (
              <a href={href} {...props} {...(external ? { target: "_blank", rel: "noopener" } : {})}>
                {children}
              </a>
            );
          },
          code({ className, children, ...props }) {
            const lang = /language-(\w+)/.exec(className || "")?.[1];
            if (lang === "mermaid") {
              return <Mermaid chart={String(children).replace(/\n$/, "")} />;
            }
            return (
              <code className={className} {...props}>
                {children}
              </code>
            );
          },
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
}
