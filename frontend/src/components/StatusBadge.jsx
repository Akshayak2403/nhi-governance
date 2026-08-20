export default function StatusBadge({ status }) {
  const map = {
    critical: { cls: "badge-critical", label: "Critical" },
    non_compliant: { cls: "badge-warning", label: "Non-Compliant" },
    compliant: { cls: "badge-compliant", label: "Compliant" },
  };
  const { cls, label } = map[status] || { cls: "badge-neutral", label: status };
  return (
    <span className={`badge ${cls}`}>
      <span className="badge-dot" />
      {label}
    </span>
  );
}
