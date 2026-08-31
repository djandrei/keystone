import type { RuleSetAttribution } from "@/lib/ruleSetsApi";

/**
 * Byline for an imported rule set: who wrote the rules, under what licence, and
 * a link to the source. Rendered wherever a rule set is shown, because the
 * licences these ship under ask for the notice to travel with the work — and
 * because they are somebody's rules.
 *
 * The author's email is deliberately not rendered: it stays in the vendored YAML
 * and LICENSE, where the notice legally lives; the repo link is the more useful
 * pointer on screen.
 */
export function RuleSetCredit({
  attribution,
  className = "",
}: {
  attribution: RuleSetAttribution | null | undefined;
  className?: string;
}) {
  if (!attribution?.author) return null;
  const { author, license, url, commit } = attribution;
  return (
    <p className={`text-xs text-fg-muted ${className}`}>
      Rules by <span className="text-fg">{author}</span>
      {license && <> · {license}</>}
      {url && (
        <>
          {" · "}
          <a
            href={url}
            target="_blank"
            rel="noreferrer noopener"
            className="underline decoration-dotted underline-offset-2 hover:text-fg"
          >
            {url.replace(/^https?:\/\/(www\.)?/, "")}
          </a>
          {commit && <> @ {commit.slice(0, 7)}</>}
        </>
      )}
    </p>
  );
}
