"""Static Shield 56 branding. Never interpolate evidence or user input here."""

import base64

from incident_analyzer.identity import PRODUCT_NAME, SUBTITLE

APP_NAME = PRODUCT_NAME

# Jordan flag: black/white/green stripes, red hoist triangle, white 7-point star.
FLAG_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 840 420">
<rect width="840" height="140" fill="#000000"/>
<rect y="140" width="840" height="140" fill="#FFFFFF"/>
<rect y="280" width="840" height="140" fill="#007A3D"/>
<path d="M0 0 420 210 0 420z" fill="#CE1126"/>
<path fill="#FFFFFF" d="M140 182.5l9.2 19.1 20.6-4.7-9.2 19.1 16.5 13.2-20.6 4.7.1 21.1-16.6-13.2-16.6 13.2.1-21.1-20.6-4.7 16.5-13.2-9.2-19.1 20.6 4.7z"/>
</svg>"""

_FLAG_URI = "data:image/svg+xml;base64," + base64.b64encode(FLAG_SVG.encode()).decode()

CSS = """<style>
:root{--s56-bg:#0B1220;--s56-surface:#152033;--s56-text:#F8FAFC;--s56-muted:#CBD5E1;
--s56-green:#008751;--s56-green-hi:#22C55E;--s56-red:#CE1126;--s56-focus:#7DD3FC;}
.s56-band{display:flex;height:6px;border-radius:3px;overflow:hidden;margin:0 0 1rem}
.s56-band span{flex:1}
.s56-header{border-left:4px solid var(--s56-red);background:var(--s56-surface);
padding:.9rem 1.1rem;border-radius:0 8px 8px 0;margin-bottom:.5rem}
.s56-header .s56-name{display:flex;align-items:center;gap:.6rem;margin:0;
font-size:clamp(1.6rem,4vw,2.2rem);font-weight:700;color:var(--s56-text);line-height:1.2}
.s56-header img{height:1.1em;width:auto;border:1px solid #475569;border-radius:2px}
.s56-header .s56-sub{margin:.25rem 0 0;color:var(--s56-muted);font-size:1rem}
/* Visible keyboard focus, >=3:1 against #0B1220 and #152033 */
a:focus-visible,button:focus-visible,[role="button"]:focus-visible,
[data-testid="stSidebarNavLink"]:focus-visible{outline:2px solid var(--s56-focus)!important;outline-offset:2px}
/* Selected sidebar navigation: green indicator */
[data-testid="stSidebarNavLink"][aria-current="page"]{box-shadow:inset 3px 0 0 var(--s56-green-hi);
background:rgba(0,135,81,.22)}
code,pre,[data-testid="stMetricValue"]{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
/* White on brand green is 4.58:1; off-white on green would fail small text AA. */
[data-testid="stBaseButton-primary"]{color:#FFFFFF;background:#008751}
</style>"""

BAND_HTML = ('<div class="s56-band" aria-hidden="true">'
             '<span style="background:#000"></span><span style="background:#FFFFFF"></span>'
             '<span style="background:#008751"></span><span style="background:#CE1126"></span></div>')

HEADER_HTML = (
    '<header class="s56-header" role="banner" aria-label="Shield 56, Security Incident Timeline Analyzer">'
    f'<h1 class="s56-name"><img src="{_FLAG_URI}" alt="Flag of Jordan" role="img">Shield 56</h1>'
    f'<p class="s56-sub">{SUBTITLE}</p></header>'
)


def render_styles(st) -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def render_header(st) -> None:
    """Static HTML only; no dynamic content is ever passed in."""
    st.markdown(BAND_HTML + HEADER_HTML, unsafe_allow_html=True)


def render_sidebar_identity(st) -> None:
    with st.sidebar:
        st.markdown(
            '<div class="s56-header" aria-label="Shield 56">'
            f'<p class="s56-name" style="font-size:1.25rem"><img src="{_FLAG_URI}" alt="Flag of Jordan" role="img">Shield 56</p>'
            f'<p class="s56-sub" style="font-size:.85rem">{SUBTITLE}</p></div>',
            unsafe_allow_html=True,
        )
        st.caption("CSV/JSONL/XML evidence, UTC timeline, and deterministic findings with source provenance.")
