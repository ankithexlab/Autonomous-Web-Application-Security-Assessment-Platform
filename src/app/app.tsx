import { RouterProvider } from "react-router"
import { AppProviders } from "./providers/app-providers"
import { router } from "./router/routes"

export function App() {
  return (
    <AppProviders>
      <RouterProvider router={router} />
    </AppProviders>
  )
}
