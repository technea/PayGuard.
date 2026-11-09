import test from "node:test";
import assert from "node:assert/strict";
import { markdownToHtml } from "../scripts/render-docs.mjs";

test("document headings receive stable fragment identifiers", () => {
  const markdown = [
    "# Whitepaper", "", "## Contents", "",
    "1. Executive Summary", "2. Product Overview", "",
    "## 1. Executive Summary", "", "Text.", "",
    "## Product Overview", "", "More text."
  ].join("\n");
  const html = markdownToHtml(markdown);
  assert.match(html, /<h1 id="whitepaper">/);
  assert.match(html, /<h2 id="1-executive-summary">/);
  assert.match(html, /<h2 id="product-overview">/);
});

test("Contents becomes an accessible list of working section links", () => {
  const markdown = [
    "## Contents", "", "1. Executive Summary", "2. Product Overview", "",
    "## 1. Executive Summary", "", "Text.", "",
    "## Product Overview", "", "More text."
  ].join("\n");
  const html = markdownToHtml(markdown);
  assert.match(html, /<nav class="doc-toc" aria-label="Whitepaper contents">/);
  assert.match(html, /<a href="#1-executive-summary">Executive Summary<\/a>/);
  assert.match(html, /<a href="#2-product-overview">Product Overview<\/a>/);
});

test("duplicate headings receive unique fragment identifiers", () => {
  const html = markdownToHtml(["## Overview", "", "First.", "", "## Overview", "", "Second."].join("\n"));
  assert.match(html, /id="overview"/);
  assert.match(html, /id="overview-2"/);
});
