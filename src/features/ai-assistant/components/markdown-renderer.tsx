import { useState } from "react"
import { Check, Copy } from "lucide-react"
import { Button } from "@/components/ui/button"
import { toast } from "sonner"

interface MarkdownRendererProps {
  content: string
}

interface CodeBlockProps {
  language: string
  code: string
}

function CodeBlock({ language, code }: CodeBlockProps) {
  const [copied, setCopied] = useState(false)

  function handleCopy() {
    navigator.clipboard.writeText(code)
    setCopied(true)
    toast.success(`${language.toUpperCase() || "Code"} snippet copied to clipboard`)
    setTimeout(() => setCopied(false), 2000)
  }

  const lines = code.trim().split("\n")

  return (
    <div className="my-3 overflow-hidden rounded-xl border border-border/80 bg-[oklch(0.12_0.005_285.82)] font-mono text-xs shadow-md">
      {/* Code Header */}
      <div className="flex items-center justify-between border-b border-white/10 bg-white/[0.04] px-4 py-2 text-muted-foreground select-none">
        <span className="text-[11px] font-bold uppercase tracking-wider text-primary font-mono">
          {language || "code"}
        </span>
        <Button
          variant="ghost"
          size="sm"
          onClick={handleCopy}
          className="h-6 px-2 text-[11px] text-muted-foreground hover:text-white"
        >
          {copied ? (
            <>
              <Check className="h-3 w-3 text-emerald-400 mr-1" />
              Copied!
            </>
          ) : (
            <>
              <Copy className="h-3 w-3 mr-1" />
              Copy
            </>
          )}
        </Button>
      </div>

      {/* Code Body */}
      <div className="overflow-x-auto p-4 leading-relaxed">
        {lines.map((line, idx) => (
          <div key={idx} className="table-row">
            <span className="table-cell select-none pr-4 text-right text-[11px] text-muted-foreground/40 font-mono">
              {idx + 1}
            </span>
            <span className="table-cell whitespace-pre font-mono text-[12px] text-emerald-300">
              {line}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

export function MarkdownRenderer({ content }: MarkdownRendererProps) {
  // Split code blocks from markdown text
  const parts = content.split(/(```[\s\S]*?```)/g)

  return (
    <div className="space-y-2 text-xs leading-relaxed">
      {parts.map((part, index) => {
        if (part.startsWith("```") && part.endsWith("```")) {
          const match = part.match(/^```(\w+)?\n([\s\S]*?)```$/)
          const language = match?.[1] || "text"
          const code = match?.[2] || part.slice(3, -3)
          return <CodeBlock key={index} language={language} code={code} />
        }

        // Standard text lines
        const lines = part.split("\n")
        return (
          <div key={index} className="space-y-1.5">
            {lines.map((line, lIdx) => {
              if (!line.trim()) return <div key={lIdx} className="h-1" />

              // Heading 3
              if (line.startsWith("### ")) {
                return (
                  <h3 key={lIdx} className="text-sm font-bold text-foreground mt-3 mb-1">
                    {line.slice(4)}
                  </h3>
                )
              }

              // Heading 4
              if (line.startsWith("#### ")) {
                return (
                  <h4 key={lIdx} className="text-xs font-bold text-foreground mt-2 mb-1">
                    {line.slice(5)}
                  </h4>
                )
              }

              // Blockquote
              if (line.startsWith("> ")) {
                return (
                  <blockquote
                    key={lIdx}
                    className="border-l-2 border-primary/60 pl-3 py-1 italic text-muted-foreground bg-primary/5 rounded-r"
                  >
                    {formatInline(line.slice(2))}
                  </blockquote>
                )
              }

              // Bullet points
              if (line.startsWith("- ") || line.startsWith("* ")) {
                return (
                  <div key={lIdx} className="flex items-start gap-2 pl-2">
                    <span className="text-primary font-bold">›</span>
                    <span className="text-foreground/90">{formatInline(line.slice(2))}</span>
                  </div>
                )
              }

              // Numbered list
              const numMatch = line.match(/^(\d+)\.\s+(.*)$/)
              if (numMatch) {
                return (
                  <div key={lIdx} className="flex items-start gap-2 pl-2">
                    <span className="font-semibold text-primary">{numMatch[1]}.</span>
                    <span className="text-foreground/90">{formatInline(numMatch[2])}</span>
                  </div>
                )
              }

              return (
                <p key={lIdx} className="text-foreground/90">
                  {formatInline(line)}
                </p>
              )
            })}
          </div>
        )
      })}
    </div>
  )
}

function formatInline(text: string = "") {
  // Bold and inline code formatting
  const tokens = text.split(/(\*\*.*?\*\*|`.*?`)/g)
  return tokens.map((token, i) => {
    if (token.startsWith("**") && token.endsWith("**")) {
      return (
        <strong key={i} className="font-bold text-foreground">
          {token.slice(2, -2)}
        </strong>
      )
    }
    if (token.startsWith("`") && token.endsWith("`")) {
      return (
        <code
          key={i}
          className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-primary"
        >
          {token.slice(1, -1)}
        </code>
      )
    }
    return token
  })
}
