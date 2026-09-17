

import { useState } from "react";
import "./App.css";

const API_BASE = import.meta.env.VITE_API_BASE || "";

interface Interface {
  name: string;
  alias: string;
  role: string | null;
  active: boolean;
}

interface Zone {
  name: string;
  interfaces: string[];
  is_wan_zone: boolean;
}

interface UploadResponse {
  hostname: string;
  version: string;
  model: string;
  interfaces: Interface[];
  zones: Zone[];
  sdwan_zones: Zone[];
}

interface AuditResponse {
  hostname: string;
  version: string;
  model: string;
  reports: {
    excel: string;
    word: string;
  };
  summary: {
    total_checks: number;
    warnings: string[];
  };
  checks?: {
    name: string;
    conform: boolean;
  }[];
}

type Step = "upload" | "info" | "select" | "options" | "audit" | "results";

function App() {
  const [step, setStep] = useState<Step>("upload");
  const [file, setFile] = useState<File | null>(null);
  const [uploadData, setUploadData] = useState<UploadResponse | null>(null);
  const [selectedWan, setSelectedWan] = useState<Set<string>>(new Set());

  const [utmLicense, setUtmLicense] = useState(false);
  const [mplsL2l, setMplsL2l] = useState(false);
  const [haCablingRedundancy, setHaCablingRedundancy] = useState(false);
  const [regleNoMatch, setRegleNoMatch] = useState<number>(0);

  const [clientName, setClientName] = useState("");
  const [siteName, setSiteName] = useState("");
  const [serialNumber, setSerialNumber] = useState("");
  const [licenseEndDate, setLicenseEndDate] = useState(""); // yyyy-mm-dd (input type=date)
  const [systemUptime, setSystemUptime] = useState("");

  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [auditResult, setAuditResult] = useState<AuditResponse | null>(null);

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (!selectedFile) return;

    setFile(selectedFile);
    setError(null);
    setLoading(true);

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const resp = await fetch(`${API_BASE}/api/upload`, {
        method: "POST",
        body: formData,
      });

      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.detail || "Upload failed");
      }

      const data: UploadResponse = await resp.json();
      setUploadData(data);

      // Auto-select WAN interfaces / zones
      const wanSet = new Set<string>();

      data.interfaces.forEach((iface) => {
        if (iface.role === "wan") wanSet.add(iface.name);
      });

      data.zones.forEach((zone) => {
        if (zone.is_wan_zone) wanSet.add(zone.name);
      });

      data.sdwan_zones.forEach((zone) => {
        if (zone.is_wan_zone) wanSet.add(zone.name);
      });

      setSelectedWan(wanSet);
      setStep("info");
    } catch (err: any) {
      setError(err.message || "Upload failed");
    } finally {
      setLoading(false);
    }
  };

  const handleWanToggle = (name: string) => {
    const newSet = new Set(selectedWan);

    if (newSet.has(name)) {
      newSet.delete(name);
    } else {
      newSet.add(name);
    }

    setSelectedWan(newSet);
  };

  const handleRunAudit = async () => {
    if (!file) return;

    console.log("=== Starting audit ===");
    console.log("File:", file.name);
    console.log("UTM License:", utmLicense);
    console.log("MPLS L2L:", mplsL2l);
    console.log("HA Cabling Redundancy:", haCablingRedundancy);
    console.log("Selected WAN interfaces:", Array.from(selectedWan));

    setStep("audit");
    setLoading(true);
    setError(null);
    setProgress(0);

    const formData = new FormData();
    formData.append("file", file);
    formData.append("utm_license", utmLicense.toString());
    formData.append("mpls_l2l", mplsL2l.toString());
    formData.append("ha_cabling_redundancy", haCablingRedundancy.toString());
    formData.append("regle_no_match", regleNoMatch.toString());
    formData.append("wan_interfaces", JSON.stringify(Array.from(selectedWan)));
    formData.append("client_name", clientName);
    formData.append("site_name", siteName);
    formData.append("serial_number", serialNumber);
    formData.append("license_end_date", licenseEndDate); 
    formData.append("system_uptime", systemUptime); 

    // Simulate progress
    const progressInterval = window.setInterval(() => {
      setProgress((p) => Math.min(p + 5, 99));
    }, 101);

    try {
      console.log("Sending request to:", `${API_BASE}/api/audit`);

      const resp = await fetch(`${API_BASE}/api/audit`, {
        method: "POST",
        body: formData,
      });

      console.log("Response status:", resp.status, resp.statusText);

      clearInterval(progressInterval);
      setProgress(100);

      if (!resp.ok) {
        let errorDetail = "Audit failed";

        try {
          const errorData = await resp.json();
          errorDetail = errorData.detail || errorData.message || errorDetail;
          console.error("Error response:", errorData);
        } catch (e) {
          const text = await resp.text();
          console.error("Error response (text):", text);
          errorDetail = text || errorDetail;
        }

        throw new Error(errorDetail);
      }

      const data: AuditResponse = await resp.json();
      console.log("Audit completed successfully:", data);

      setAuditResult(data);
      setStep("results");
    } catch (err: any) {
      const errorMessage = err.message || "Audit failed";

      console.error("=== Audit Error ===");
      console.error("Error message:", errorMessage);
      console.error("Error object:", err);
      console.error("Stack trace:", err.stack);

      setError(errorMessage);
      setStep("options");
    } finally {
      setLoading(false);
      clearInterval(progressInterval);
      console.log("=== Audit request finished ===");
    }
  };

  const handleDownload = (url: string, filename: string) => {
    const fullUrl = url.startsWith("http") ? url : `${API_BASE}${url}`;
    window.open(fullUrl, "_blank");
  };

  return (
    <div className="app">
      <header className="header">
        <h1>Vysion</h1>
        <p className="subtitle">Audit Configuration FortiGate</p>
      </header>

      <main className="main">
        {step === "upload" && (
          <div className="step">
            <h2>Etape 1 : Upload Configuration</h2>

            <div className="upload-area">
              <input
                type="file"
                accept=".conf"
                onChange={handleUpload}
                disabled={loading}
                id="file-input"
                style={{ display: "none" }}
              />

              <label htmlFor="file-input" className="upload-button">
                {loading ? "Processing..." : "Select FortiGate .conf file"}
              </label>

              {file && <p className="file-name">Selected: {file.name}</p>}
            </div>

            {error && <div className="error">{error}</div>}
          </div>
        )}

        {step === "info" && uploadData && (
          <div className="step">
            <h2>Etape 2 : Renseignements</h2>
            <div className="info-box">
              <p>
                <strong>Hostname:</strong> {uploadData.hostname} | <strong>Version:</strong> {uploadData.version} |{" "}
                <strong>Model:</strong> {uploadData.model}
              </p>
            </div>

            <div className="options-form">
              <label className="checkbox-item">
                <span>Nom du client</span>
                <input
                  type="text"
                  value={clientName}
                  onChange={(e) => setClientName(e.target.value)}
                  className="text-input"
                />
              </label>

              <label className="checkbox-item">
                <span>Nom du site</span>
                <input
                  type="text"
                  value={siteName}
                  onChange={(e) => setSiteName(e.target.value)}
                  className="text-input"
                />
              </label>

              <label className="checkbox-item">
                <span>Numéro de série</span>
                <input
                  type="text"
                  value={serialNumber}
                  onChange={(e) => setSerialNumber(e.target.value)}
                  className="text-input"
                />
              </label>

              <label className="checkbox-item">
                <span>Date de fin de licence</span>
                <input
                  type="date"
                  value={licenseEndDate}
                  onChange={(e) => setLicenseEndDate(e.target.value)}
                  className="date-input"
                />
              </label>

              <label className="checkbox-item">
                <span>System Uptime</span>
                <input
                  type="date"
                  value={systemUptime}
                  onChange={(e) => setSystemUptime(e.target.value)}
                  className="date-input"
                />
              </label>
            </div>

            <div className="button-group">
              <button onClick={() => setStep("upload")} className="button secondary">
                Back
              </button>

              <button
                onClick={() => setStep("select")}
                className="button primary"
              >
                Continue
              </button>
            </div>
          </div>
        )}

        {step === "select" && uploadData && (
          <div className="step">
            <h2>Etape 3 : Sélection des WAN Interfaces</h2>
            <div className="selection-section">
              <h3>Interfaces WAN à sélectionner</h3>

              <div className="checkbox-list">
                {uploadData.interfaces.map((iface) => (
                  <label key={iface.name} className="checkbox-item">
                    <input
                      type="checkbox"
                      checked={selectedWan.has(iface.name)}
                      onChange={() => handleWanToggle(iface.name)}
                    />
                    <span>
                      {iface.name}
                      {iface.alias && ` (${iface.alias})`}
                      {iface.role === "wan" && " [WAN]"}
                    </span>
                  </label>
                ))}
              </div>
            </div>

            {uploadData.zones.length > 0 && (
              <div className="selection-section">
                <h3>Zones WAN à sélectionner</h3>

                <div className="checkbox-list">
                  {uploadData.zones.map((zone) => (
                    <label key={zone.name} className="checkbox-item">
                      <input
                        type="checkbox"
                        checked={selectedWan.has(zone.name)}
                        onChange={() => handleWanToggle(zone.name)}
                      />
                      <span>
                        Zone: {zone.name} ({zone.interfaces.join(", ")})
                        {zone.is_wan_zone && " [WAN]"}
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            )}

            {uploadData.sdwan_zones.length > 0 && (
              <div className="selection-section">
                <h3>SD-WAN Zones</h3>

                <div className="checkbox-list">
                  {uploadData.sdwan_zones.map((zone) => (
                    <label key={zone.name} className="checkbox-item">
                      <input
                        type="checkbox"
                        checked={selectedWan.has(zone.name)}
                        onChange={() => handleWanToggle(zone.name)}
                      />
                      <span>
                        SD-WAN Zone: {zone.name} ({zone.interfaces.join(", ")})
                        {zone.is_wan_zone && " [WAN]"}
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            )}

            <div className="button-group">
              <button onClick={() => setStep("upload")} className="button secondary">
                Back
              </button>

              <button
                onClick={() => setStep("options")}
                className="button primary"
                disabled={selectedWan.size === 0}
              >
                Continue ({selectedWan.size} selected)
              </button>
            </div>
          </div>
        )}

        {step === "options" && (
          <div className="step">
            <h2>Etape 4 : Options d'audit</h2>

            <div className="options-form">
              <label className="checkbox-item">
                <input
                  type="checkbox"
                  checked={utmLicense}
                  onChange={(e) => setUtmLicense(e.target.checked)}
                />
                <span>Licence UTM Valide</span>
              </label>

              <label className="checkbox-item">
                <input
                  type="checkbox"
                  checked={mplsL2l}
                  onChange={(e) => setMplsL2l(e.target.checked)}
                />
                <span>Lien MPLS ou L2L</span>
              </label>

              <label className="checkbox-item">
                <input
                  type="checkbox"
                  checked={haCablingRedundancy}
                  onChange={(e) => setHaCablingRedundancy(e.target.checked)}
                />
                <span>Redondance câblage HA</span>
              </label>

              <label className="checkbox-item" style={{ alignItems: "flex-start" }}>
                <div>
                  <span>Nombre de règles sans match</span>

                  <div style={{ marginTop: "6px", color: "#666", fontSize: "0.85rem" }}>
                    Filtrez <strong>sur '&lt;=0'</strong> sur la colonne <strong>"Hit Count"</strong> des Firewall policies
                  </div>
                </div>

                <input
                  type="number"
                  min={0}
                  step={1}
                  value={regleNoMatch}
                  onChange={(e) => setRegleNoMatch(Math.max(0, Number(e.target.value)))}
                  style={{ width: 60, marginLeft: "12px" }}
                />
              </label>


            </div>

            <div className="button-group">
              <button onClick={() => setStep("select")} className="button secondary">
                Back
              </button>

              <button onClick={handleRunAudit} className="button primary">
                Run Audit
              </button>
            </div>
          </div>
        )}

        {step === "audit" && (
          <div className="step">
            <h2>Running Audit...</h2>

            <div className="progress-container">
              <div className="progress-bar">
                <div className="progress-fill" style={{ width: `${progress}%` }} />
              </div>
              <p className="progress-text">{progress}%</p>
            </div>

            {error && <div className="error">{error}</div>}
          </div>
        )}

        {step === "results" && auditResult && (
          <div className="step">
            <h2>Audit Complete</h2>

            <div className="info-box">
              <p>
                <strong>Hostname:</strong> {auditResult.hostname} | <strong>Version:</strong> {auditResult.version} |{" "}
                <strong>Model:</strong> {auditResult.model}
              </p>

              <p>
                <strong>Total Checks:</strong> {auditResult.summary.total_checks}
              </p>
            </div>

            {auditResult.summary.warnings.length > 0 && (
              <div className="warning-box">
                <h3>Warnings</h3>
                <ul>
                  {auditResult.summary.warnings.map((w, i) => (
                    <li key={i}>{w}</li>
                  ))}
                </ul>
              </div>
            )}

            {(() => {
              const nonConformChecks = (auditResult.checks ?? []).filter((c) => !c.conform);

              return nonConformChecks.length > 0 ? (
                <div className="reports-section">
                  <h3>Check-list de contrôles basiques non conformes</h3>

                  <div className="checks-table-wrapper">
                    <table className="checks-table">
                      <thead>
                        <tr>
                          <th>Contrôle</th>
                          <th className="checks-status-col">Statut</th>
                        </tr>
                      </thead>
                      <tbody>
                        {nonConformChecks.map((c, idx) => (
                          <tr key={idx}>
                            <td className="checks-name">{c.name}</td>
                            <td className="checks-status">
                              <span className="status-icon ko">✕</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                <div className="reports-section">
                  <h3>Contrôles</h3>
                  <div className="info-box" style={{ marginBottom: 0 }}>
                    ✅ Aucun contrôle non conforme détecté.
                  </div>
                </div>
              );
            })()}

            {/* Download reports : bloc séparé */}
            <div className="reports-section">
              <h3>Download Reports</h3>

              <div className="button-group">
                <button
                  onClick={() => handleDownload(auditResult.reports.excel, "audit.xlsx")}
                  className="button primary"
                >
                  Download Excel Report
                </button>

                <button
                  onClick={() => handleDownload(auditResult.reports.word, "audit.docx")}
                  className="button primary"
                >
                  Download Word Report
                </button>
              </div>
            </div>

            <div className="button-group">
              <button
                onClick={() => {
                  setStep("upload");
                  setFile(null);
                  setUploadData(null);
                  setAuditResult(null);
                  setSelectedWan(new Set());
                  setUtmLicense(false);
                  setMplsL2l(false);
                  setHaCablingRedundancy(false);
                  setRegleNoMatch(0);
                  setClientName("");
                  setSiteName("");
                  setSerialNumber("");
                  setLicenseEndDate("");
                  setSystemUptime("");
                }}
                className="button secondary"
              >
                Start New Audit
              </button>
            </div>
          </div>
        )}

      </main>

      <footer className="footer">
        <p>Vysion - V2.0</p>
      </footer>
    </div>
  );
}

export default App;
