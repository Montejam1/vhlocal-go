import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** shadcn-style class combiner: conditional classes, de-duplicated/merged. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function fmtDate(sec?: number): string {
  if (!sec) return "";
  return new Date(sec * 1000).toLocaleDateString();
}

export function fmtDateTime(sec?: number): string {
  if (!sec) return "";
  return new Date(sec * 1000).toLocaleString();
}

export function fmtDuration(sec?: number): string {
  const s = Math.max(0, Math.floor(sec || 0));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}
