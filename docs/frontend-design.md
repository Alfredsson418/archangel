# Frontend Design

The dashboard visual identity follows [the Archangel poster](../assets/archangel_poster.png). Keep the interface clear, restrained, responsive, and accessible.

## Visual system

- Use the existing CSS custom properties in `app/web/static/styles.css`: `--paper` (`#f3f6f8`), `--white` (`#fff`), `--ink` (`#142b49`), `--muted` (`#718096`), `--line` (`#d9e2eb`), `--magenta` (`#bd1979`), `--indigo` (`#643875`), `--blue` (`#0e5075`), and `--teal` (`#17a6ad`).
- Keep light paper surfaces and dark navy text. The sidebar is solid blue; use the magenta-to-indigo-to-deep-blue gradient sparingly for small accents such as the logo mark.
- Use Manrope for general interface text and DM Mono for compact labels, navigation indexes, table headings, and other data-oriented metadata, as configured by `--sans` and `--mono`.
- Prefer generous spacing, restrained typography, flat surfaces, and fine borders. Use color for emphasis and state, with readable contrast; do not rely on color alone to convey status.

## Responsive and accessible behavior

- Support desktop, wide-screen, and phone layouts. Use available width on large screens and keep narrow layouts readable and operable without horizontal page scrolling.
- Use semantic HTML and associated form labels. Support keyboard navigation and visible focus indicators.
- Provide meaningful status and error text. Do not communicate errors or state using color alone.

Build pages from the shared `base.html` layout and its Jinja blocks. Put page-specific content in the relevant template instead of duplicating the shell or navigation.
