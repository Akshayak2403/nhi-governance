import { useRef } from "react";

export default function FileDropzone({ label, hint, icon, file, onFile }) {
  const inputRef = useRef(null);

  return (
    <div
      className={`dropzone ${file ? "filled" : ""}`}
      onClick={() => inputRef.current?.click()}
      onDragOver={(e) => e.preventDefault()}
      onDrop={(e) => {
        e.preventDefault();
        const dropped = e.dataTransfer.files?.[0];
        if (dropped) onFile(dropped);
      }}
    >
      <input
        ref={inputRef}
        type="file"
        accept="application/json"
        hidden
        onChange={(e) => e.target.files?.[0] && onFile(e.target.files[0])}
      />
      <div className="dz-icon">{icon}</div>
      <div className="dz-label">{label}</div>
      <div className="dz-hint">{hint}</div>
      {file && <div className="dz-file">{file.name}</div>}
    </div>
  );
}
