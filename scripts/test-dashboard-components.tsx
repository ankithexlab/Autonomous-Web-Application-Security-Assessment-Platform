import React from "react"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router"
import { RecentActivity } from "../src/features/dashboard/components/recent-activity"
import { SeverityBadge } from "../src/features/dashboard/components/severity-badge"
import { RecentScanCard } from "../src/features/dashboard/components/recent-scan-card"

function runDashboardResilienceTests() {
  console.log("=== STARTING DASHBOARD COMPONENT REGRESSION TESTS ===")

  // 1. Test RecentActivity with undefined
  try {
    const html = renderToStaticMarkup(<RecentActivity activities={undefined} />)
    console.log("✓ PASS: RecentActivity renders with activities=undefined (HTML length: " + html.length + ")")
  } catch (err) {
    console.error("✗ FAIL: RecentActivity failed with activities=undefined:", err)
    process.exit(1)
  }

  // 2. Test RecentActivity with empty array
  try {
    const html = renderToStaticMarkup(<RecentActivity activities={[]} />)
    console.log("✓ PASS: RecentActivity renders with activities=[] (HTML length: " + html.length + ")")
  } catch (err) {
    console.error("✗ FAIL: RecentActivity failed with activities=[]:", err)
    process.exit(1)
  }

  // 3. Test RecentActivity with all known activity types
  const knownTypes = [
    "scan_completed",
    "scan_failed",
    "scan_cancelled",
    "scan_started",
    "scan_running",
    "scan_queued",
    "finding_discovered",
    "finding_resolved",
    "report_generated",
    "target_created",
    "project_created",
  ]

  const knownActivities = knownTypes.map((type, idx) => ({
    id: `act-known-${idx}`,
    type: type as any,
    title: `Test ${type}`,
    description: `Description for ${type}`,
    timestamp: new Date().toISOString(),
    severity: (type === "finding_discovered" ? "high" : undefined) as any,
  }))

  try {
    const html = renderToStaticMarkup(<RecentActivity activities={knownActivities} />)
    for (const t of knownTypes) {
      if (!html.includes(`Test ${t}`)) {
        throw new Error(`Rendered HTML missing text for type: ${t}`)
      }
    }
    console.log(`✓ PASS: RecentActivity successfully rendered all ${knownTypes.length} supported activity types`)
  } catch (err) {
    console.error("✗ FAIL: RecentActivity failed on known types:", err)
    process.exit(1)
  }

  // 4. Test RecentActivity with unknown, exotic, or unexpected types
  const unknownActivities = [
    {
      id: "act-unk-1",
      type: "unrecognized_future_event" as any,
      title: "Unrecognized Event Title",
      description: "Unrecognized Event Desc",
      timestamp: "2026-11-08T12:00:00Z",
    },
    {
      id: "act-unk-2",
      type: "weird_security_alert" as any,
      title: "Weird Alert",
      description: "Weird alert description",
      timestamp: null,
    },
    {
      id: "act-unk-3",
      type: "" as any,
      title: "Empty String Type",
      description: "Empty type description",
      timestamp: "invalid-date-string",
    },
  ]

  try {
    const html = renderToStaticMarkup(<RecentActivity activities={unknownActivities} />)
    if (!html.includes("Unrecognized Event Title") || !html.includes("Weird Alert")) {
      throw new Error("Rendered HTML missing unknown event content")
    }
    console.log("✓ PASS: RecentActivity safely renders unknown and empty activity types without throwing")
  } catch (err) {
    console.error("✗ FAIL: RecentActivity threw on unknown activity types:", err)
    process.exit(1)
  }

  // 5. Test RecentActivity with missing, null, and malformed activity entries
  const malformedActivities = [
    {} as any,
    { id: undefined, type: undefined, title: undefined, description: undefined, timestamp: undefined } as any,
    { id: "partial-1", type: null as any } as any,
  ]

  try {
    const html = renderToStaticMarkup(<RecentActivity activities={malformedActivities} />)
    console.log("✓ PASS: RecentActivity safely handles malformed/null/missing activity items (HTML length: " + html.length + ")")
  } catch (err) {
    console.error("✗ FAIL: RecentActivity threw on malformed items:", err)
    process.exit(1)
  }

  // 6. Test SeverityBadge resilience
  const testSeverities = [
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "CRITICAL",
    "HIGH",
    "Medium",
    "unknown_severity",
    "",
    null,
    undefined,
  ]

  try {
    for (const sev of testSeverities) {
      const html = renderToStaticMarkup(<SeverityBadge severity={sev as any} />)
      if (html.length === 0) {
        throw new Error(`Empty render for severity: ${sev}`)
      }
    }
    console.log(`✓ PASS: SeverityBadge safely rendered ${testSeverities.length} variations (standard, uppercase, unknown, null, undefined)`)
  } catch (err) {
    console.error("✗ FAIL: SeverityBadge failed on severity tests:", err)
    process.exit(1)
  }

  // 7. Test RecentScanCard resilience
  try {
    const htmlNull = renderToStaticMarkup(
      <MemoryRouter>
        <RecentScanCard scan={null} />
      </MemoryRouter>
    )
    const htmlUndefined = renderToStaticMarkup(
      <MemoryRouter>
        <RecentScanCard scan={undefined} />
      </MemoryRouter>
    )
    const htmlMalformed = renderToStaticMarkup(
      <MemoryRouter>
        <RecentScanCard scan={{ id: "", target_name: "", target_url: "", scan_type: "", status: "", created_at: null, completed_at: null }} />
      </MemoryRouter>
    )
    console.log("✓ PASS: RecentScanCard safely handles null, undefined, and empty scan objects")
  } catch (err) {
    console.error("✗ FAIL: RecentScanCard failed:", err)
    process.exit(1)
  }

  console.log("=== ALL DASHBOARD COMPONENT REGRESSION TESTS PASSED ===")
}

runDashboardResilienceTests()
