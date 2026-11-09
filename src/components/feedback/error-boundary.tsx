import React, { Component, type ReactNode } from "react"
import { ErrorFallback } from "./error-fallback"

interface Props {
  children?: ReactNode
  fallbackTitle?: string
  fallbackMessage?: string
}

interface State {
  hasError: boolean
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  }

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  public componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error("ErrorBoundary caught an unhandled exception:", error, errorInfo)
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null })
  }

  public render() {
    if (this.state.hasError) {
      return (
        <ErrorFallback
          title={this.props.fallbackTitle || "Application Error Detected"}
          message={
            this.props.fallbackMessage ||
            this.state.error?.message ||
            "An unexpected UI exception occurred in this component subtree."
          }
          onRetry={this.handleReset}
        />
      )
    }

    return this.props.children
  }
}
