import { PanelLeft } from "lucide-react";
import { useLocation } from "react-router";

import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { AuthDisabledBanner } from "@/components/common/auth-disabled-banner";
import { RefreshIntervalSelector } from "@/components/common/refresh-interval";
import { ThemeToggle } from "@/components/common/theme-toggle";
import { useUIStore } from "@/stores/ui-store";

const ROUTE_LABEL: Record<string, string> = {
  "/": "Dashboard",
  "/events": "Events",
  "/pipeline": "Pipeline",
  "/analyst": "Analyst",
  "/settings": "Settings",
  "/login": "Sign in",
};

export function TopBar() {
  const toggleSidebar = useUIStore((s) => s.toggleSidebar);
  const location = useLocation();
  const label =
    ROUTE_LABEL[location.pathname] ??
    (location.pathname.startsWith("/analyst/") ? "Analyst" : "Falcosidekick");

  return (
    <div className="sticky top-0 z-20 border-b border-border/60 bg-background/90 backdrop-blur">
      <div className="flex h-14 items-center gap-2 px-4">
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleSidebar}
          aria-label="Toggle navigation sidebar"
        >
          <PanelLeft className="size-4" aria-hidden />
        </Button>
        <div className="flex-1 text-sm font-medium text-muted-foreground">
          {label}
        </div>
        <RefreshIntervalSelector />
        <Separator orientation="vertical" className="mx-1 h-5" />
        <AuthDisabledBanner compact />
        <ThemeToggle />
      </div>
    </div>
  );
}
