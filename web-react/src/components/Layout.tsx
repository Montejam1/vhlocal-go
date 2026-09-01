import { NavLink, Outlet } from "react-router-dom";
import {
  LayoutGrid,
  Home,
  Search,
  FileText,
  BookMarked,
  BookOpen,
  Settings,
  Moon,
  Sun,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", label: "Home", icon: Home, end: true },
  { to: "/apps", label: "Apps", icon: LayoutGrid },
  { to: "/scans", label: "Scans", icon: Search },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/ledger", label: "Ledger", icon: BookMarked },
  { to: "/docs", label: "Docs", icon: BookOpen },
  { to: "/settings", label: "Settings", icon: Settings },
];

function ThemeToggle() {
  const [dark, setDark] = useState(
    document.documentElement.getAttribute("data-theme") !== "light",
  );
  const toggle = () => {
    const next = dark ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem("vh-theme", next);
    } catch {}
    setDark(!dark);
  };
  return (
    <button
      onClick={toggle}
      className="h-9 w-9 grid place-items-center rounded-lg text-text-2 hover:text-text-1 hover:bg-surface-2"
      title="Toggle light / dark"
    >
      {dark ? <Moon size={17} /> : <Sun size={17} />}
    </button>
  );
}

export function Layout() {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex items-center gap-3 border-b border-line bg-surface-1 px-4 h-14">
        <div className="flex items-center gap-2 text-accent">
          <ShieldCheck size={22} />
          <div>
            <div className="text-[15px] font-semibold text-text-1 leading-none">vhlocal</div>
            <div className="text-[10.5px] text-text-3">VulnHunter engine</div>
          </div>
        </div>
        <nav className="ml-4 flex items-center gap-0.5">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[13px] font-medium transition-colors",
                  isActive
                    ? "bg-accent-weak text-accent"
                    : "text-text-2 hover:text-text-1 hover:bg-surface-2",
                )
              }
            >
              <Icon size={15} />
              {label}
            </NavLink>
          ))}
        </nav>
        <span className="flex-1" />
        <ThemeToggle />
      </header>
      <main className="flex-1 overflow-y-auto px-6 py-6">
        <div className="mx-auto max-w-6xl">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
