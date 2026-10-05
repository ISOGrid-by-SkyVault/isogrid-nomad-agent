import { useMemo, useRef, useState } from "react";

// One measure over time for one service: a single series on a single axis,
// so no legend (the title names it). The line wears the one data hue; every
// label stays in text tokens. Hovering shows a crosshair and the exact value.

export type ChartPoint = { t: number; v: number };

type Props = {
  title: string;
  points: ChartPoint[];
  from: number; // unix seconds, left edge
  to: number; // unix seconds, right edge
  format: (v: number) => string;
  ceiling?: { value: number; label: string }; // e.g. the memory limit
};

const W = 520;
const H = 150;
const PAD = { left: 8, right: 8, top: 10, bottom: 20 };

function niceMax(v: number): number {
  if (v <= 0) return 1;
  const pow = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / pow;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * pow;
}

function clock(t: number, spanSeconds: number): string {
  const d = new Date(t * 1000);
  return spanSeconds > 36 * 3600
    ? d.toLocaleDateString(undefined, { month: "short", day: "numeric" })
    : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

export function Chart({ title, points, from, to, format, ceiling }: Props) {
  const ref = useRef<SVGSVGElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  const span = Math.max(1, to - from);

  const { path, area, max, xy } = useMemo(() => {
    const peak = Math.max(0, ...points.map((p) => p.v));
    const top = niceMax(ceiling && ceiling.value <= peak * 4 ? Math.max(peak, ceiling.value) : peak);
    const x = (t: number) => PAD.left + ((t - from) / span) * (W - PAD.left - PAD.right);
    const y = (v: number) => H - PAD.bottom - (v / top) * (H - PAD.top - PAD.bottom);
    const coords = points.map((p) => [x(p.t), y(p.v)] as const);
    const line = coords.map(([px, py], i) => `${i ? "L" : "M"}${px.toFixed(1)},${py.toFixed(1)}`).join(" ");
    const base = H - PAD.bottom;
    const fill = coords.length
      ? `${line} L${coords[coords.length - 1][0].toFixed(1)},${base} L${coords[0][0].toFixed(1)},${base} Z`
      : "";
    return { path: line, area: fill, max: top, xy: { x, y, coords } };
  }, [points, from, span, ceiling]);

  const onMove = (event: React.PointerEvent<SVGSVGElement>) => {
    const box = ref.current?.getBoundingClientRect();
    if (!box || !points.length) return;
    const px = ((event.clientX - box.left) / box.width) * W;
    let best = 0;
    for (let i = 1; i < xy.coords.length; i++) {
      if (Math.abs(xy.coords[i][0] - px) < Math.abs(xy.coords[best][0] - px)) best = i;
    }
    setHover(best);
  };

  const last = points[points.length - 1];
  const shown = hover !== null && points[hover] ? points[hover] : last;
  const ceilingY = ceiling && ceiling.value <= max ? xy.y(ceiling.value) : null;

  return (
    <figure className="chart">
      <figcaption>
        <span className="chart-title">{title}</span>
        <span className="chart-value">
          {shown ? format(shown.v) : "no data"}
          {shown && <span className="chart-when"> {hover !== null ? new Date(shown.t * 1000).toLocaleTimeString() : "now"}</span>}
        </span>
      </figcaption>
      <svg
        ref={ref}
        viewBox={`0 0 ${W} ${H}`}
        role="img"
        aria-label={`${title}: ${last ? format(last.v) : "no data"} at the latest reading, scale up to ${format(max)}`}
        onPointerMove={onMove}
        onPointerLeave={() => setHover(null)}
      >
        <line className="chart-grid" x1={PAD.left} x2={W - PAD.right} y1={PAD.top} y2={PAD.top} />
        <line className="chart-axis" x1={PAD.left} x2={W - PAD.right} y1={H - PAD.bottom} y2={H - PAD.bottom} />
        <text className="chart-tick" x={PAD.left} y={PAD.top - 2}>
          {format(max)}
        </text>
        <text className="chart-tick" x={PAD.left} y={H - 5}>
          {clock(from, span)}
        </text>
        <text className="chart-tick" x={W - PAD.right} y={H - 5} textAnchor="end">
          {clock(to, span)}
        </text>
        {ceilingY !== null && ceiling && (
          <>
            <line className="chart-ceiling" x1={PAD.left} x2={W - PAD.right} y1={ceilingY} y2={ceilingY} />
            <text className="chart-tick" x={W - PAD.right} y={ceilingY - 3} textAnchor="end">
              {ceiling.label}
            </text>
          </>
        )}
        {area && <path className="chart-area" d={area} />}
        {path && <path className="chart-line" d={path} />}
        {points.length === 1 && <circle className="chart-dot" cx={xy.coords[0][0]} cy={xy.coords[0][1]} r={4} />}
        {hover !== null && xy.coords[hover] && (
          <>
            <line className="chart-cross" x1={xy.coords[hover][0]} x2={xy.coords[hover][0]} y1={PAD.top} y2={H - PAD.bottom} />
            <circle className="chart-dot" cx={xy.coords[hover][0]} cy={xy.coords[hover][1]} r={4} />
          </>
        )}
      </svg>
    </figure>
  );
}
