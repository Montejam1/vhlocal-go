import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Mermaid } from "./Mermaid";

/** Render markdown (threat model / report bodies). A ```mermaid fenced block is
 *  rendered as a live diagram; everything else uses GFM (tables, lists, code). */
export function Markdown({ children }: { children: string }) {
  return (
    <div className="md max-w-[960px]">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
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
