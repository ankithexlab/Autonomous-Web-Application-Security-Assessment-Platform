import { useState, useEffect } from "react"
import { Link, useNavigate, useSearchParams } from "react-router"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { motion, AnimatePresence } from "framer-motion"
import {
  Eye,
  EyeOff,
  Loader2,
  Lock,
  CheckCircle2,
  Check,
  X,
} from "lucide-react"
import { toast } from "sonner"
import { cn } from "@/utils"
import { ROUTES } from "@/constants"
import { useAuthStore } from "@/stores/auth-store"
import {
  resetPasswordSchema,
  type ResetPasswordValues,
} from "../schemas/auth-schemas"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

const PASSWORD_RULES = [
  { label: "At least 8 characters", test: (v: string) => v.length >= 8 },
  { label: "One uppercase letter", test: (v: string) => /[A-Z]/.test(v) },
  { label: "One lowercase letter", test: (v: string) => /[a-z]/.test(v) },
  { label: "One number", test: (v: string) => /[0-9]/.test(v) },
]

export function ResetPasswordPage() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const resetPassword = useAuthStore((s) => s.resetPassword)
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  const [isSuccess, setIsSuccess] = useState(false)

  const token = searchParams.get("token") ?? ""

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors, isSubmitting },
  } = useForm<ResetPasswordValues>({
    resolver: zodResolver(resetPasswordSchema),
    defaultValues: { password: "", confirmPassword: "" },
  })

  const passwordValue = watch("password")

  // Auto-redirect after success
  useEffect(() => {
    if (!isSuccess) return
    const timer = setTimeout(() => navigate(ROUTES.AUTH.LOGIN), 3000)
    return () => clearTimeout(timer)
  }, [isSuccess, navigate])

  const onSubmit = async (data: ResetPasswordValues) => {
    try {
      await resetPassword(token, data.password)
      setIsSuccess(true)
      toast.success("Password reset successful", {
        description: "You can now sign in with your new password.",
      })
    } catch {
      toast.error("Reset failed", {
        description: "This reset link may have expired. Please request a new one.",
      })
    }
  }

  return (
    <AnimatePresence mode="wait">
      {!isSuccess ? (
        <motion.div
          key="form"
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -12 }}
          transition={{ duration: 0.3, ease: "easeOut" }}
        >
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
            {/* Header */}
            <div className="space-y-1.5 text-center">
              <h2 className="text-2xl font-bold tracking-tight text-foreground">
                Reset password
              </h2>
              <p className="text-sm text-muted-foreground">
                Enter your new password below
              </p>
            </div>

            {/* New Password */}
            <div className="space-y-2">
              <Label htmlFor="password">New password</Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  placeholder="Enter new password"
                  autoComplete="new-password"
                  aria-invalid={!!errors.password}
                  className="pr-10"
                  {...register("password")}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground transition-colors hover:text-foreground"
                  tabIndex={-1}
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
              {errors.password && (
                <p className="text-xs text-destructive">
                  {errors.password.message}
                </p>
              )}

              {/* Password strength indicators */}
              {passwordValue && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  className="space-y-1.5 pt-1"
                >
                  {PASSWORD_RULES.map((rule) => {
                    const passed = rule.test(passwordValue)
                    return (
                      <div
                        key={rule.label}
                        className="flex items-center gap-2 text-xs"
                      >
                        {passed ? (
                          <Check className="h-3 w-3 text-emerald-500" />
                        ) : (
                          <X className="h-3 w-3 text-muted-foreground" />
                        )}
                        <span
                          className={cn(
                            passed
                              ? "text-emerald-500"
                              : "text-muted-foreground",
                          )}
                        >
                          {rule.label}
                        </span>
                      </div>
                    )
                  })}
                </motion.div>
              )}
            </div>

            {/* Confirm Password */}
            <div className="space-y-2">
              <Label htmlFor="confirmPassword">Confirm new password</Label>
              <div className="relative">
                <Input
                  id="confirmPassword"
                  type={showConfirm ? "text" : "password"}
                  placeholder="Confirm new password"
                  autoComplete="new-password"
                  aria-invalid={!!errors.confirmPassword}
                  className="pr-10"
                  {...register("confirmPassword")}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirm((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground transition-colors hover:text-foreground"
                  tabIndex={-1}
                >
                  {showConfirm ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
              {errors.confirmPassword && (
                <p className="text-xs text-destructive">
                  {errors.confirmPassword.message}
                </p>
              )}
            </div>

            {/* Submit */}
            <Button
              type="submit"
              className="w-full"
              disabled={isSubmitting}
            >
              {isSubmitting ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Lock className="mr-2 h-4 w-4" />
              )}
              {isSubmitting ? "Resetting..." : "Reset password"}
            </Button>
          </form>
        </motion.div>
      ) : (
        <motion.div
          key="success"
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, ease: "easeOut" }}
          className="space-y-6 text-center"
        >
          {/* Success icon */}
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-emerald-500/10">
            <CheckCircle2 className="h-8 w-8 text-emerald-500" />
          </div>

          {/* Success message */}
          <div className="space-y-2">
            <h2 className="text-2xl font-bold tracking-tight text-foreground">
              Password reset!
            </h2>
            <p className="text-sm text-muted-foreground">
              Your password has been successfully updated. Redirecting to sign
              in...
            </p>
          </div>

          {/* Manual link */}
          <Link
            to={ROUTES.AUTH.LOGIN}
            className="text-sm font-medium text-primary hover:underline"
          >
            Sign in now
          </Link>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
