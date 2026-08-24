//! Emit printable pass cards as a LaTeX document.
//!
//! Rendering happens in the owner's toolchain, so no QR encoder, image codec,
//! font, or PDF writer enters this binary (AGENTS.md C-19).

use std::fmt::Write as _;

use crate::policy::{Registry, reachable};

const PREAMBLE: &str = r"\documentclass[a4paper,11pt]{article}
\usepackage[margin=15mm]{geometry}
\usepackage[nolinks]{qrcode}
\usepackage{tikz}
\usepackage{helvet}
\renewcommand{\familydefault}{\sfdefault}
\pagestyle{empty}

% level=H tolerates a scuffed card. padding adds the 4-module quiet zone the QR
% specification requires; the package omits it by default, and a card trimmed
% flush to the code will not scan reliably without it.
\qrset{level=H,padding}

% \passcard{label}{hint}{url}
\newcommand{\passcard}[3]{%
  \begin{tikzpicture}
    \node[draw,rounded corners=2mm,line width=0.3pt,
          inner sep=4mm,minimum width=62mm,minimum height=78mm] (c) {%
      \begin{minipage}{54mm}
        \centering
        \qrcode[height=34mm]{#3}\\[4mm]
        {\large\bfseries #1}\\[1.5mm]
        {\footnotesize #2}
      \end{minipage}};
  \end{tikzpicture}%
}

\begin{document}
\noindent
";

/// Render the document. Pure: the same config produces the same bytes anywhere,
/// which is why the standalone binary and the add-on agree.
#[must_use]
pub fn document(registry: &Registry, tokens: &[(String, String)]) -> String {
    let base = registry.base_url();
    let mut out = String::from(PREAMBLE);
    let mut cards = 0usize;

    for (pass_id, token) in tokens {
        let Some(pass) = registry.passes().iter().find(|p| p.id.as_ref() == pass_id) else {
            continue;
        };
        for (suffix, device, verb) in reachable(registry, pass) {
            let hint = format!("Scan to switch {}", verb.to_hint());
            let url = format!("{base}/t/{token}{suffix}");
            if cards > 0 && cards.is_multiple_of(2) {
                out.push_str("\n\n\\vspace{6mm}\n\n\\noindent\n");
            } else if cards > 0 {
                out.push_str("\n\\hfill\n");
            }
            let _ = write!(
                out,
                "\\passcard{{{}}}{{{}}}{{{}}}",
                escape(&device.label),
                escape(&hint),
                escape(&url)
            );
            cards += 1;
        }
    }

    out.push_str("\n\\end{document}\n");
    out
}

/// Escape the characters TeX treats specially. Device labels and pass labels are
/// owner-supplied, so they cross this boundary before reaching the document.
fn escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '\\' => out.push_str(r"\textbackslash{}"),
            '&' | '%' | '$' | '#' | '_' | '{' | '}' => {
                out.push('\\');
                out.push(c);
            }
            '~' => out.push_str(r"\textasciitilde{}"),
            '^' => out.push_str(r"\textasciicircum{}"),
            _ => out.push(c),
        }
    }
    out
}

trait Hint {
    fn to_hint(self) -> &'static str;
}

impl Hint for crate::domain::Verb {
    fn to_hint(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tex_special_characters_are_escaped() {
        assert_eq!(escape("100% & rising"), r"100\% \& rising");
        assert_eq!(escape("a_b"), r"a\_b");
        assert_eq!(escape("{x}"), r"\{x\}");
        assert_eq!(escape(r"a\b"), r"a\textbackslash{}b");
    }

    #[test]
    fn a_document_carries_a_card_per_reachable_call() {
        let raw: crate::config::RawConfig = serde_yaml_ng::from_str(
            r#"
version: 1
tunnel: {token: "eyJhIjoidGVzdCJ9", public_url: "https://gp.example.com"}
devices: [{ id: lamp, label: "Living room lamp", entity: light.a }]
passes: [{ id: tag, tokens: ["K7QF3M2X9WPLNA4RTVBC6DHJ8Z"], device: lamp, verb: on }]
"#,
        )
        .expect("yaml");
        let reg = crate::config::compile(&raw).expect("compiles");
        let doc = document(
            &reg,
            &[("tag".to_owned(), "K7QF3M2X9WPLNA4RTVBC6DHJ8Z".to_owned())],
        );
        assert!(doc.contains(r"\begin{document}"));
        assert!(doc.contains(r"\end{document}"));
        assert!(doc.contains("https://gp.example.com/t/K7QF3M2X9WPLNA4RTVBC6DHJ8Z"));
        // An arity-0 pass reaches exactly one call, so exactly one card is
        // emitted after the preamble's macro definition.
        let body = doc.split(r"\begin{document}").nth(1).expect("body");
        assert_eq!(body.matches(r"\passcard{").count(), 1);
        assert!(body.contains(r"{Living room lamp}"), "{body}");
        assert!(body.contains("{Scan to switch on}"), "{body}");
    }
}
