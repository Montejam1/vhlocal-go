import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { Applications } from "@/pages/Applications";
import { Dashboard } from "@/pages/Dashboard";
import { Scans } from "@/pages/Scans";
import { Reports } from "@/pages/Reports";
import { Ledger } from "@/pages/Ledger";
import { Docs } from "@/pages/Docs";
import { Placeholder } from "@/components/Placeholder";

// Served by the Python engine at /app, so the router basename matches.
export default function App() {
  return (
    <BrowserRouter basename="/app">
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="apps" element={<Applications />} />
          <Route path="scans" element={<Scans />} />
          <Route path="reports" element={<Reports />} />
          <Route path="ledger" element={<Ledger />} />
          <Route path="docs" element={<Docs />} />
          <Route path="settings" element={<Placeholder title="Settings" note="Coming next." />} />
          <Route path="*" element={<Placeholder title="Not found" note="No such view." />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
