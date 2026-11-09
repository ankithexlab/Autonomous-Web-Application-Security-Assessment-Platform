import { useState } from "react"
import { Link } from "react-router"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { motion, AnimatePresence } from "framer-motion"
import { ArrowLeft, Loader2, Mail, Send } from "lucide-react"
import { toast } from "sonner"
import { ROUTES } from "@/constants"
import { useAuthStore } from "@/stores/auth-store"
import {
  forgotPasswordSchema,
  type ForgotPasswordValues,
} from "../schemas/auth-schemas"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export function ForgotPasswordPage() {
  const forgotPassword = useAuthStore((s) => s.forgotPassword)
  const [isSuccess, setIsSuccess] = useState(false)
  const [submittedEmail, setSubmittedEmail] = useState("")

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<ForgotPasswordValues>({
    resolver: zodResolver(forgotPasswordSchema),
    defaultValues: { email: "" },
  })

  const onSubmit = async (data: ForgotPasswordValues) => {
    try {
      await forgotPassword(data.email)
      setSubmittedEmail(data.email)
      setIsSuccess(true)
      toast.success("Reset link sent", {
        description: "Check your email for the password reset link.",
      })
    } catch {
      toast.error("Failed to send reset link", {
        description: "Please try again later.",
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
                Forgot password?
              </h2>
              <p className="text-sm text-muted-foreground">
                Enter your email and we&apos;ll send you a reset link
              </p>
            </div>

            {/* Email */}
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="you@company.com"
                autoComplete="email"
                aria-invalid={!!errors.email}
                {...register("email")}
              />
              {errors.email && (
                <p className="text-xs text-destructive">
                  {errors.email.message}
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
                <Send className="mr-2 h-4 w-4" />
              )}
              {isSubmitting ? "Sending..." : "Send reset link"}
            </Button>

            {/* Back to login */}
            <Link
              to={ROUTES.AUTH.LOGIN}
              className="flex items-center justify-center gap-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to sign in
            </Link>
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
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-primary/10">
            <Mail className="h-8 w-8 text-primary" />
          </div>

          {/* Success message */}
          <div className="space-y-2">
            <h2 className="text-2xl font-bold tracking-tight text-foreground">
              Check your email
            </h2>
            <p className="text-sm text-muted-foreground">
              We sent a password reset link to
            </p>
            <p className="text-sm font-medium text-foreground">
              {submittedEmail}
            </p>
          </div>

          <p className="text-xs text-muted-foreground">
            Didn&apos;t receive the email? Check your spam folder or{" "}
            <button
              type="button"
              onClick={() => setIsSuccess(false)}
              className="font-medium text-primary hover:underline"
            >
              try again
            </button>
          </p>

          {/* Back to login */}
          <Link
            to={ROUTES.AUTH.LOGIN}
            className="flex items-center justify-center gap-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to sign in
          </Link>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
