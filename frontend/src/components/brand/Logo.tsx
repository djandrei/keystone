import { cn } from "@/lib/cn";

/** The Keystone mark: an arch of stone voussoirs locked by the amber keystone.
 *  Mirrors assets/branding/keystone-mark.svg. */
export function Logo({ className, ...props }: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 100 100"
      role="img"
      aria-label="Keystone"
      className={cn("h-8 w-8", className)}
      {...props}
    >
      <title>Keystone</title>
      <polygon points="13,31 37,23 43,66 19,74" fill="#46577A" stroke="#0B1220" strokeWidth="1.6" strokeLinejoin="round" />
      <polygon points="87,31 63,23 57,66 81,74" fill="#46577A" stroke="#0B1220" strokeWidth="1.6" strokeLinejoin="round" />
      <polygon points="13,31 37,23 39,29.5 15.7,37.4" fill="#6B7EA6" />
      <polygon points="87,31 63,23 61,29.5 84.3,37.4" fill="#6B7EA6" />
      <polygon points="37,20 63,20 57,66 43,66" fill="#F59E0B" stroke="#0B1220" strokeWidth="1.6" strokeLinejoin="round" />
      <polygon points="37,20 63,20 59.8,26 40.2,26" fill="#FBBF24" />
    </svg>
  );
}
