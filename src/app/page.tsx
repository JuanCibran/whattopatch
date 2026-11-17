import { RadarBoard } from "@/components/RadarBoard";
import { Breaches, Hero, HowWeRank, News } from "@/components/Sections";
import { getRadar } from "@/lib/radar";

export default async function Home() {
  const radar = await getRadar();
  return (
    <main>
      <Hero radar={radar} />
      <div className="mt-14">
        <RadarBoard now={radar.now} soon={radar.soon} watch={radar.watch} trending={radar.trending} asOf={radar.generatedAt} />
      </div>
      <Breaches radar={radar} />
      <News radar={radar} />
      <HowWeRank radar={radar} />
    </main>
  );
}
