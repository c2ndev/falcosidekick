import { useNavigate } from "react-router"

import logoIcon from "@/assets/logo-icon.svg"
import { LoginForm } from "@/components/auth/login-form"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useUIStore } from "@/stores/ui-store"

export function LoginPage() {
  const navigate = useNavigate()
  const authEnabled = useUIStore((s) => s.authEnabled)

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <div className="w-full max-w-sm space-y-6">
        <div className="flex flex-col items-center gap-2">
          <img src={logoIcon} alt="" aria-hidden className="size-16" />
          <div className="text-center">
            <h1 className="text-xl font-semibold text-foreground">Falco Sidekick</h1>
            <p className="text-sm text-muted-foreground">Sign in to continue</p>
          </div>
        </div>

        <Card>
          <CardHeader className="space-y-1">
            <CardTitle className="text-base">Sign in</CardTitle>
            <CardDescription>
              Use the credentials configured for this deployment.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <LoginForm onSuccess={() => navigate("/", { replace: true })} />
            {authEnabled === false && (
              <p className="mt-4 text-xs text-muted-foreground">
                Authentication is disabled in this deployment. You can access the app without signing
                in.
              </p>
            )}
          </CardContent>
        </Card>

        <p className="text-center text-xs text-muted-foreground">
          Falco Sidekick v3 · part of the Falco Project
        </p>
      </div>
    </div>
  )
}

export default LoginPage
