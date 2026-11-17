import Link from "next/link";

export default function NotFound() {
  return (
    <main className="mx-auto max-w-[1180px] px-5 pt-14 sm:px-8">
      <h1 className="display text-[clamp(3rem,9vw,6rem)]">Page not found</h1>
      <p className="mt-4 max-w-[60ch] text-[1.1875rem]">
        Vulnerability pages use the CVE ID in the address, like <code>/cve/CVE-2024-3400</code>. Check the ID, or go back to
        the board.
      </p>
      <p className="mt-6">
        <Link href="/">Go to the board</Link>
      </p>
    </main>
  );
}
