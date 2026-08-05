// Merged dashboard: Dashboard-2 shell (animated sidebar, WebSocket live refresh,
// onLogout prop, neon styling) + all Dashboard v1 features (user card, persisted
// selection, restored selection on mount, full logout cleanup).
//
// NOTE: This is plain JSX for your own repo — copy it over your Dashboard.jsx.
// It expects ../components/SystemList, ../components/SystemDetails and ../api.
import React, { useEffect, useState, useRef } from "react";
import SystemList from "../components/SystemList";
import SystemDetails from "../components/SystemDetails";
import { API } from "../api";
import { Menu } from "lucide-react";

export default function Dashboard({ onLogout }) {
  const [user, setUser] = useState(null);
  const [systems, setSystems] = useState([]);
  const [riskMap, setRiskMap] = useState({});
  const [selected, setSelected] = useState(null);
  const [lastSyncedAt, setLastSyncedAt] = useState(null);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const wsRef = useRef(null);

  // Load user + previously selected agent ONCE
  useEffect(() => {
    const storedUser = localStorage.getItem("itd_user");
    const storedAgent = localStorage.getItem("selected_agent");

    if (storedUser) {
      try {
        setUser(JSON.parse(storedUser));
      } catch {
        setUser(null);
      }
    }

    if (storedAgent) setSelected(storedAgent);
  }, []);

  const load = async () => {
    try {
      const [systemsRes, riskRes] = await Promise.all([
        API.listSystems(),
        API.getAllRisk(),
      ]);

      const list = Array.isArray(systemsRes)
        ? systemsRes
        : systemsRes?.systems || [];
      setSystems(list);

      const map = {};
      for (const r of Array.isArray(riskRes) ? riskRes : []) {
        if (r?.agent_id) map[r.agent_id] = r;
      }
      setRiskMap(map);

      // Selection priority: stored -> previous -> first endpoint -> none
      setSelected((prev) => {
        const stored = localStorage.getItem("selected_agent");

        if (stored && list.some((s) => s.agent_id === stored)) return stored;
        if (prev && list.some((s) => s.agent_id === prev)) return prev;

        const first = list[0]?.agent_id || null;
        if (first) localStorage.setItem("selected_agent", first);
        return first;
      });

      setLastSyncedAt(Date.now());
    } catch (err) {
      console.error("Dashboard load failed", err);
    }
  };

  useEffect(() => {
    load();
    const poll = setInterval(load, 30000);
    wsRef.current = createWS(() => load());
    return () => {
      clearInterval(poll);
      wsRef.current?.close?.();
    };
  }, []);

  const handleLogout = () => {
    localStorage.removeItem("itd_user");
    localStorage.removeItem("itd_login_time");
    localStorage.removeItem("selected_agent");
    onLogout?.();
  };

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100vh",
        width: "100vw",
        overflow: "hidden",
        backgroundColor: "#050a14",
        color: "#fff",
        fontFamily: "'Rajdhani', 'Share Tech Mono', sans-serif",
      }}
    >
      {/* HEADER */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "1rem 2rem",
          backgroundColor: "rgba(5, 10, 20, 0.9)",
          borderBottom: "1px solid rgba(0, 240, 255, 0.2)",
          zIndex: 100,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "1.5rem" }}>
          <button
            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            style={{
              background: isSidebarOpen
                ? "rgba(0, 240, 255, 0.2)"
                : "rgba(0, 240, 255, 0.05)",
              border: "1px solid #00f0ff",
              color: "#00f0ff",
              padding: "0.5rem",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              transition: "all 0.3s ease",
              boxShadow: isSidebarOpen
                ? "inset 0 0 10px rgba(0,240,255,0.5)"
                : "none",
            }}
          >
            <Menu size={24} />
          </button>

          <div>
            <div
              style={{
                fontSize: "1.5rem",
                fontWeight: "bold",
                color: "#00f0ff",
                letterSpacing: "2px",
                textTransform: "uppercase",
              }}
            >
              Insider Threat Detection
            </div>
            <div
              style={{
                fontSize: "0.8rem",
                opacity: 0.7,
                marginTop: "4px",
                fontFamily: "'Share Tech Mono', monospace",
              }}
            >
              Endpoints: {systems.length}
              {lastSyncedAt && (
                <>
                  {" "}
                  <span style={{ color: "#00f0ff" }}>//</span> Last synced{" "}
                  {new Date(lastSyncedAt).toLocaleTimeString()}
                </>
              )}
            </div>
          </div>
        </div>

        <div style={{ display: "flex", gap: "1rem", alignItems: "center" }}>
          {user && (
            <div style={{ textAlign: "right", lineHeight: 1.3 }}>
              <div style={{ fontWeight: "bold", color: "#00f0ff" }}>
                {user.name || user.username}
              </div>
              {user.department && (
                <div style={{ fontSize: "0.75rem", opacity: 0.7 }}>
                  {user.department}
                </div>
              )}
            </div>
          )}

          <button
            onClick={handleLogout}
            style={{
              background: "transparent",
              border: "1px solid #ff003c",
              color: "#ff003c",
              padding: "0.4rem 1rem",
              cursor: "pointer",
              fontFamily: "inherit",
              fontWeight: "bold",
              textShadow: "0 0 5px #ff003c",
              boxShadow: "inset 0 0 5px rgba(255,0,60,0.2)",
            }}
          >
            LOGOUT SYSTEM
          </button>
        </div>
      </div>

      {/* MAIN CONTENT */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        {/* SIDEBAR */}
        <div
          style={{
            width: isSidebarOpen ? "320px" : "0px",
            opacity: isSidebarOpen ? 1 : 0,
            flexShrink: 0,
            transition: "all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1)",
            borderRight: isSidebarOpen
              ? "1px solid rgba(0, 240, 255, 0.2)"
              : "none",
            backgroundColor: "rgba(0, 0, 0, 0.4)",
            overflowX: "hidden",
            overflowY: "auto",
          }}
        >
          <div style={{ width: "320px", padding: isSidebarOpen ? "1rem" : "0" }}>
            {/* USER CARD */}
            {user && (
              <div
                style={{
                  marginBottom: "1rem",
                  padding: "1rem",
                  border: "1px solid rgba(0, 240, 255, 0.4)",
                  background: "rgba(0, 240, 255, 0.05)",
                }}
              >
                <div
                  style={{
                    color: "#00f0ff",
                    fontWeight: "bold",
                    letterSpacing: "1px",
                    textTransform: "uppercase",
                  }}
                >
                  {user.name || user.username}
                </div>
                {user.department && (
                  <div style={{ fontSize: "0.8rem", opacity: 0.7, marginTop: 2 }}>
                    {user.department}
                  </div>
                )}
                {user.agent_id && (
                  <div
                    style={{
                      fontSize: "0.7rem",
                      opacity: 0.6,
                      marginTop: 6,
                      fontFamily: "'Share Tech Mono', monospace",
                    }}
                  >
                    {user.agent_id}
                  </div>
                )}
              </div>
            )}

            {/* SYSTEM LIST */}
            <SystemList
              systems={systems}
              riskMap={riskMap}
              selected={selected}
              onSelect={(id) => {
                setSelected(id);
                localStorage.setItem("selected_agent", id);
                if (window.innerWidth < 1000) setIsSidebarOpen(false);
              }}
            />
          </div>
        </div>

        {/* DETAILS */}
        <div style={{ flex: 1, position: "relative", overflowY: "auto" }}>
          {selected ? (
            <SystemDetails agentId={selected} />
          ) : (
            <div
              style={{
                height: "100%",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: "1.5rem",
                color: "#00f0ff",
                letterSpacing: "2px",
                fontFamily: "'Share Tech Mono', monospace",
              }}
            >
              AWAITING ENDPOINT SELECTION...
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function createWS(onMessage) {
  try {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.hostname}:8000/ws`);
    ws.onmessage = () => onMessage();
    return ws;
  } catch {
    return { close() {} };
  }
}
