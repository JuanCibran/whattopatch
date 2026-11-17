import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { ImageResponse } from "next/og";
import { productName } from "@/lib/format";
import { getRadar } from "@/lib/radar";

export const alt = "WhatToPatch: the vulnerability attackers are exploiting that you should fix first";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

const fontsDir = join(process.cwd(), "src/app/fonts");
const display = await readFile(join(fontsDir, "BigShoulders-800.woff"));
const body = await readFile(join(fontsDir, "AtkinsonHyperlegibleNext-400.woff"));
const bodyBold = await readFile(join(fontsDir, "AtkinsonHyperlegibleNext-700.woff"));

export default async function OpenGraphImage() {
  const radar = await getRadar();
  const top = radar.top;
  const name = top ? productName(top.vendor, top.product) : "";
  return new ImageResponse(
    (
      <div style={{ width: "100%", height: "100%", display: "flex", background: "#edf1f5", padding: 56, fontFamily: "Body" }}>
        <div
          style={{
            display: "flex",
            width: "100%",
            background: "#fbfcfd",
            border: "2px solid #c8d1dd",
            borderRadius: "8px 22px 22px 8px",
          }}
        >
          <div style={{ width: 34, background: "#c8202f", borderRadius: "6px 0 0 6px", display: "flex" }} />
          <div style={{ display: "flex", flexDirection: "column", justifyContent: "space-between", padding: "40px 52px", flex: 1 }}>
            <div style={{ display: "flex", flexDirection: "column" }}>
              <div style={{ fontSize: 30, color: "#566179", fontFamily: "BodyBold" }}>WhatToPatch</div>
              <div style={{ fontSize: 132, lineHeight: 0.9, color: "#17223b", fontFamily: "Display", marginTop: 12 }}>
                Fix this first
              </div>
            </div>
            <div style={{ display: "flex", flexDirection: "column" }}>
              {top ? (
                <>
                  <div style={{ fontSize: 40, color: "#17223b", fontFamily: "BodyBold" }}>{name || top.id}</div>
                  <div style={{ fontSize: 30, color: "#566179", marginTop: 6 }}>
                    {`${top.id}${top.kev?.ransomware ? ", used by ransomware" : ""}`}
                  </div>
                </>
              ) : (
                <div style={{ fontSize: 36, color: "#17223b" }}>What attackers are exploiting now, and what to do.</div>
              )}
              <div style={{ fontSize: 26, color: "#566179", marginTop: 18 }}>
                {`${radar.counts.kevLast7} added to CISA's exploited list this week`}
              </div>
            </div>
          </div>
        </div>
      </div>
    ),
    {
      ...size,
      fonts: [
        { name: "Display", data: display, weight: 800, style: "normal" },
        { name: "Body", data: body, weight: 400, style: "normal" },
        { name: "BodyBold", data: bodyBold, weight: 700, style: "normal" },
      ],
    },
  );
}
