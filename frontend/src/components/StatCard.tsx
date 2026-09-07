interface Props {
  label: string;
  value: number | string;
  accent?: "blue" | "green" | "red" | "amber";
}

const accentMap: Record<string, string> = {
  blue: "text-cyan-400",
  green: "text-emerald-400",
  red: "text-red-400",
  amber: "text-amber-400",
};

export default function StatCard({ label, value, accent = "blue" }: Props) {
  return (
    <div className="bg-soc-panel rounded-xl border border-soc-border p-5 shadow-lg shadow-black/20">
      <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">{label}</p>
      <p className={`text-3xl font-bold mt-2 ${accentMap[accent]}`}>{value}</p>
    </div>
  );
}