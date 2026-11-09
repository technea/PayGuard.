import { readFileSync, existsSync } from "node:fs";
import path from "node:path";

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

export function markdownToHtml(markdown) {
  if (!markdown) return "";
  let text = markdown.replace(/\r\n/g, "\n");

  // Preserve fenced code blocks
  const codeBlocks = [];
  text = text.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, (_match, lang, code) => {
    const placeholder = `__PAYGUARD_CODEBLOCK_${codeBlocks.length}__`;
    codeBlocks.push(
      `<pre><code class="language-${escapeHtml(lang || "plaintext")}">${escapeHtml(code.trimEnd())}</code></pre>`
    );
    return placeholder;
  });

  // Preserve tables
  const tables = [];
  text = text.replace(/((?:^|\n)\|[^\n]+\|\n\|[-:\s|]+\|\n(?:\|[^\n]+\|\n?)+)/g, (_match, tableBlock) => {
    const placeholder = `__PAYGUARD_TABLE_${tables.length}__`;
    const lines = tableBlock.trim().split("\n");
    if (lines.length < 3) return tableBlock;

    const parseRow = line =>
      line
        .replace(/^\||\|$/g, "")
        .split("|")
        .map(cell => cell.trim());

    const headers = parseRow(lines[0]);
    const rows = lines.slice(2).map(parseRow);

    let htmlTable = "<table><thead><tr>";
    for (const h of headers) {
      htmlTable += `<th>${formatInline(h)}</th>`;
    }
    htmlTable += "</tr></thead><tbody>";
    for (const r of rows) {
      htmlTable += "<tr>";
      for (const cell of r) {
        htmlTable += `<td>${formatInline(cell)}</td>`;
      }
      htmlTable += "</tr>";
    }
    htmlTable += "</tbody></table>";
    tables.push(`<div class="table-scroll" role="region" aria-label="Scrollable table" tabindex="0">${htmlTable}</div>`);
    return "\n\n" + placeholder + "\n\n";
  });

  // Headings
  const headingIds = new Map();
  const createHeadingId = (heading) => {
    const base = heading
      .toLowerCase()
      .replace(/&amp;/g, " and ")
      .replace(/&[^;]+;/g, " ")
      .replace(/<[^>]*>/g, "")
      .normalize("NFKD")
      .replace(/[\\u0300-\\u036f]/g, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "") || "section";
    const count = headingIds.get(base) || 0;
    headingIds.set(base, count + 1);
    return count ? `${base}-${count + 1}` : base;
  };
  text = text.replace(/^#### (.*?)$/gm, (_m, h) => `<h4 id="${createHeadingId(h)}">${formatInline(h)}</h4>`);
  text = text.replace(/^### (.*?)$/gm, (_m, h) => `<h3 id="${createHeadingId(h)}">${formatInline(h)}</h3>`);
  text = text.replace(/^## (.*?)$/gm, (_m, h) => `<h2 id="${createHeadingId(h)}">${formatInline(h)}</h2>`);
  text = text.replace(/^# (.*?)$/gm, (_m, h) => `<h1 id="${createHeadingId(h)}">${formatInline(h)}</h1>`);
  // Horizontal rules
  text = text.replace(/^---$/gm, '<hr style="border:0;border-top:1px solid rgba(255,255,255,0.1);margin:2rem 0;">');

  // Blockquotes / Alerts
  text = text.replace(/^> \[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\n([\s\S]*?)(?=\n\n|$)/gm, (_m, type, body) => {
    const alertColors = {
      NOTE: "var(--cyan)",
      TIP: "var(--emerald)",
      IMPORTANT: "var(--violet)",
      WARNING: "var(--amber)",
      CAUTION: "var(--rose)"
    };
    const color = alertColors[type] || "var(--cyan)";
    return `<blockquote style="border-left: 4px solid ${color}; background: rgba(255,255,255,0.03); padding: 0.85rem 1.25rem; border-radius: 0 8px 8px 0; margin: 1.25rem 0;">
      <strong style="color: ${color}; text-transform: uppercase; font-size: 0.8rem; letter-spacing: 0.05em;">[${type}]</strong><br/>
      ${formatInline(body.replace(/^> /gm, ""))}
    </blockquote>`;
  });
  text = text.replace(/^> (.*?)$/gm, (_m, quote) => `<blockquote>${formatInline(quote)}</blockquote>`);

  // Lists (unordered)
  text = text.replace(/((?:^[*-] .*\n?)+)/gm, (_m, listBlock) => {
    const items = listBlock
      .trim()
      .split("\n")
      .map(item => `<li>${formatInline(item.replace(/^[*-] /, ""))}</li>`)
      .join("");
    return `<ul>${items}</ul>\n`;
  });

  // Lists (ordered)
  text = text.replace(/((?:^\d+\. .*\n?)+)/gm, (_m, listBlock) => {
    const items = listBlock
      .trim()
      .split("\n")
      .map(item => `<li>${formatInline(item.replace(/^\d+\. /, ""))}</li>`)
      .join("");
    return `<ol>${items}</ol>\n`;
  });

  // Paragraphs
  const blocks = text.split(/\n\s*\n/);
  const formattedBlocks = blocks.map(b => {
    const trimmed = b.trim();
    if (!trimmed) return "";
    if (
      trimmed.startsWith("<h1") ||
      trimmed.startsWith("<h2") ||
      trimmed.startsWith("<h3") ||
      trimmed.startsWith("<h4") ||
      trimmed.startsWith("<ul") ||
      trimmed.startsWith("<ol") ||
      trimmed.startsWith("<blockquote") ||
      trimmed.startsWith("<hr") ||
      trimmed.startsWith("<table") ||
      trimmed.startsWith("__PAYGUARD_CODEBLOCK_") ||
      trimmed.startsWith("__PAYGUARD_TABLE_")
    ) {
      return trimmed;
    }
    return `<p>${formatInline(trimmed)}</p>`;
  });

  let output = formattedBlocks.filter(Boolean).join("\n\n");

  // Restore tables
  tables.forEach((t, i) => {
    output = output.replace(`__PAYGUARD_TABLE_${i}__`, t);
  });

  // Restore code blocks
  codeBlocks.forEach((cb, i) => {
    output = output.replace(`__PAYGUARD_CODEBLOCK_${i}__`, cb);
  });

  // Turn a document's numbered Contents list into a navigable, accessible table of contents.
  output = output.replace(/(<h2 id="contents">\\s*Contents\\s*<\\/h2>\\s*)<ol>([\\s\\S]*?)<\\/ol>/i, (_match, heading, items) => {
    const linkedItems = items.replace(/<li>([\\s\\S]*?)<\\/li>/g, (_item, label) => {
      const plainLabel = label.replace(/<[^>]*>/g, "").replace(/&amp;/g, "&").trim();
      const target = createContentsTarget(plainLabel);
      return `<li><a href="#${target}">${label}</a></li>`;
    });
    return `${heading}<nav class="doc-toc" aria-label="Whitepaper contents"><ol>${linkedItems}</ol></nav>`;
  });

  return output;
}

function createContentsTarget(label) {
  return label
    .toLowerCase()
    .replace(/&amp;/g, " and ")
    .replace(/&[^;]+;/g, " ")
    .replace(/<[^>]*>/g, "")
    .normalize("NFKD")
    .replace(/[\\u0300-\\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "") || "section";
}

function formatInline(str) {
  if (!str) return "";
  let s = str;
  // Inline code
  s = s.replace(/`([^`]+)`/g, (_m, code) => `<code>${escapeHtml(code)}</code>`);
  // Bold
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  // Italic
  s = s.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  // Markdown links
  s = s.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_m, label, href) => {
    let target = href;
    if (target.endsWith(".md")) {
      target = target.replace(/\.md$/, "");
      if (!target.startsWith("/") && !target.startsWith("http")) {
        target = "/docs/" + target;
      }
    }
    const isExt = target.startsWith("http");
    return `<a href="${escapeHtml(target)}"${isExt ? ' target="_blank" rel="noopener noreferrer"' : ""}>${escapeHtml(label)}</a>`;
  });
  return s;
}

export function renderDocPage(docSlug, templateHtml) {
  const allowedDocs = {
    whitepaper: "docs/whitepaper.md",
    faq: "docs/faq.md",
    architecture: "docs/architecture.md",
    "security-model": "docs/security-model.md",
    "mcp-tools": "docs/mcp-tools.md",
    "api-reference": "docs/api-reference.md",
    "ai-security-agent": "docs/ai-security-agent.md",
    "getting-started": "docs/getting-started.md",
    "limitations-roadmap": "docs/limitations-roadmap.md",
    "judge-brief": "docs/judge-brief.md",
    "demo-script": "docs/demo-script.md",
    index: "README.md",
    overview: "README.md"
  };

  const relPath = allowedDocs[docSlug] || allowedDocs.overview;
  const fullPath = path.join(process.cwd(), relPath);

  let markdown = "";
  try {
    if (existsSync(fullPath)) {
      markdown = readFileSync(fullPath, "utf8");
    }
  } catch (err) {
    markdown = `# Error loading document\n\nCould not load \`${relPath}\`: ${err.message}`;
  }

  const renderedContent = markdownToHtml(markdown);
  return templateHtml.replace("{{DOC_CONTENT}}", renderedContent);
}
