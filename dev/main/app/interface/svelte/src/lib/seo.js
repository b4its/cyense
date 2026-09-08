// JSON-LD structured data for /tools — the analysis' §A1/§4.2 finding:
// tool names existed only as anchor text (naive extractors lose names);
// "microdata Product/SoftwareApplication would improve both SEO and
// interoperability". We ship JSON-LD from the same single catalogue source:
//   * CollectionPage + ItemList  → the tools view (current page of cards)
//   * SoftwareApplication (page) → when a tool drawer is open

// One tool → schema.org SoftwareApplication node.
export function toolNode(t, categoryLabel) {
  const node = {
    '@type': 'SoftwareApplication',
    name: t.name,
    url: t.url || undefined,
    applicationCategory: categoryLabel || t.category || undefined,
    description: t.description || undefined,
    keywords: [...new Set([
      ...(t.tags || []), ...(t.you_have || []), ...(t.you_get || []),
    ])].join(', ') || undefined,
    sameAs: t.source_page || undefined,
  }
  if ((t.platforms || []).length) node.operatingSystem = t.platforms.join(', ')
  if (t.pricing) node.offers = { '@type': 'Offer', category: t.pricing }
  return node
}

// Tools view → CollectionPage with the CURRENT page's cards as an ItemList
// (position numbers mirror what a viewer sees).
export function catalogJsonLd(catalog, pageItems, { position0 = 0, matched = null } = {}) {
  const catLabel = {}
  for (const c of catalog?.categories || []) catLabel[c.id] = c.label
  return {
    '@context': 'https://schema.org',
    '@type': 'CollectionPage',
    name: 'Cyense — Katalog Tools (Pentest + OSINT)',
    description: 'Katalog pentest (Kali-style) + pustaka OSINT OSINT Radar dengan lapis metodologi: workflows, pivot map, Toolbench, Case File.',
    url: typeof location !== 'undefined' ? `${location.origin}${location.pathname}#/tools` : undefined,
    mainEntity: {
      '@type': 'ItemList',
      numberOfItems: matched ?? catalog?.total ?? 0,
      itemListElement: (pageItems || []).map((t, i) => ({
        '@type': 'ListItem',
        position: position0 + i + 1,
        item: toolNode(t, catLabel[t.category]),
      })),
    },
  }
}

// Drawer open → single SoftwareApplication page node.
export function toolJsonLd(catalog, tool) {
  const catLabel = (catalog?.categories || []).find((c) => c.id === tool.category)?.label
  return { '@context': 'https://schema.org', ...toolNode(tool, catLabel) }
}
