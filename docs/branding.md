# Shield 56 — visual identity

**Security Incident Timeline Analyzer** · suggested repository: `shield-56`.

| Role | Color |
| --- | --- |
| Main background | `#0B1220` |
| Surface | `#152033` |
| Primary text | `#F8FAFC` |
| Secondary text | `#CBD5E1` |
| Jordan-inspired green | `#008751` |
| Jordan-inspired red | `#CE1126` |
| White accent | `#FFFFFF` |

Use supported Streamlit theme settings, native controls, and a small stylesheet
for the header, decorative band, and focus treatment. The flag is a labeled
graphic, not the only way to identify the country. All interface copy is English.

Keep evidence separate from branding: raw logs, IDs, hashes, and UTC timestamps
use monospace plain text. Never insert uploaded content into unsafe HTML.
Future severity styling must use labels such as “High” or “Low”; red branding
must not imply a finding exists.

The requested palette may need lighter focus outlines and control borders to
meet WCAG AA. Test text at 4.5:1 and meaningful non-text indicators at 3:1.
Brand decoration is not a severity indicator.

Measured: off-white `#F8FAFC` on green `#008751` is only **4.38:1**.
Use white `#FFFFFF` on green for small primary-action text (**4.58:1**).
The focus outline is light blue `#7DD3FC` (**9.79:1** on the slate surface);
the selected-navigation indicator is bright green `#22C55E` (**7.16:1**).
These accessibility adjustments supplement, rather than replace, the brand palette.

Future report heading: **Shield 56 — Incident Investigation Report**.
Example filenames: `shield56_incident_report.md`,
`shield56_evidence_manifest.json`. These downloads are not implemented yet.
Printed reports must use clear headings, textual severity and source references;
do not depend on colored backgrounds.

Verification results are recorded in `PROJECT_SPEC.md`. Current checks cannot
validate unavailable evidence controls, future severity components or print output.
