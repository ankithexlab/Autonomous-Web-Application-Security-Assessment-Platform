import { useEffect, useState, useMemo } from "react"
import { motion } from "framer-motion"
import { Plus, FolderKanban } from "lucide-react"
import { Button } from "@/components/ui/button"
import { EmptyState } from "@/components/feedback"
import { toast } from "sonner"
import { ProjectStatsBar } from "../components/project-stats-bar"
import { ProjectCard } from "../components/project-card"
import { ProjectFilters } from "../components/project-filters"
import { ProjectModal } from "../components/project-modal"
import { DeleteProjectDialog } from "../components/delete-project-dialog"
import { projectsService } from "@/services/projects.service"
import type { Project, ProjectStatus, ProjectRiskLevel } from "@/types"

export function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([])
  const [search, setSearch] = useState("")
  const [statusFilter, setStatusFilter] = useState<ProjectStatus | "all">("all")
  const [riskFilter, setRiskFilter] = useState<ProjectRiskLevel | "all">("all")

  // Modal & Dialog state
  const [modalOpen, setModalOpen] = useState(false)
  const [editingProject, setEditingProject] = useState<Project | null>(null)
  const [deleteProject, setDeleteProject] = useState<Project | null>(null)

  const loadProjects = () => {
    projectsService
      .getProjects()
      .then((data) => {
        setProjects(data)
      })
      .catch(() => {
        toast.error("Failed to load projects from server")
      })
  }

  useEffect(() => {
    loadProjects()
  }, [])

  // Filtered projects computation
  const filteredProjects = useMemo(() => {
    return projects.filter((p) => {
      if (search) {
        const q = search.toLowerCase()
        const match =
          p.name.toLowerCase().includes(q) ||
          p.description?.toLowerCase().includes(q) ||
          p.owner.toLowerCase().includes(q) ||
          p.tags.some((t) => t.toLowerCase().includes(q))
        if (!match) return false
      }

      if (statusFilter !== "all" && p.status !== statusFilter) return false
      if (riskFilter !== "all" && p.riskLevel !== riskFilter) return false

      return true
    })
  }, [projects, search, statusFilter, riskFilter])

  /* ── CRUD Actions ── */
  function handleCreateNew() {
    setEditingProject(null)
    setModalOpen(true)
  }

  function handleEdit(project: Project) {
    setEditingProject(project)
    setModalOpen(true)
  }

  function handleToggleStatus(project: Project, newStatus: ProjectStatus) {
    projectsService
      .updateProject(project.id, { status: newStatus })
      .then((updated) => {
        setProjects((prev) => prev.map((p) => (p.id === updated.id ? updated : p)))
        toast.success(`Project status updated to ${newStatus}`)
      })
      .catch(() => {
        toast.error("Failed to update project status")
      })
  }

  async function handleSaveProject(data: Partial<Project>) {
    try {
      if (data.id) {
        // Edit existing
        const updated = await projectsService.updateProject(data.id, {
          name: data.name,
          description: data.description,
          status: data.status,
          risk_level: data.riskLevel,
          tags: data.tags,
        })
        setProjects((prev) => prev.map((p) => (p.id === updated.id ? updated : p)))
        toast.success("Project updated successfully")
      } else {
        // Create new
        const created = await projectsService.createProject({
          name: data.name || "Untitled Project",
          description: data.description,
          status: data.status || "active",
          risk_level: data.riskLevel || "medium",
          tags: data.tags,
        })
        setProjects((prev) => [created, ...prev])
        toast.success("Project created successfully")
      }
      setModalOpen(false)
    } catch {
      toast.error("Failed to save project")
    }
  }

  async function handleDeleteConfirm(projectId: string) {
    try {
      await projectsService.deleteProject(projectId)
      setProjects((prev) => prev.filter((p) => p.id !== projectId))
      toast.success("Project deleted")
    } catch {
      toast.error("Failed to delete project")
    } finally {
      setDeleteProject(null)
    }
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">
            Security Projects
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Organize security assessment scopes, manage targets, and track risk metrics across environments
          </p>
        </div>
        <Button onClick={handleCreateNew} className="gap-2 self-start font-semibold">
          <Plus className="h-4 w-4" />
          Create Project
        </Button>
      </motion.div>

      {/* Stats Summary Bar */}
      <ProjectStatsBar projects={projects} />

      {/* Filters Toolbar */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.3, delay: 0.1 }}
      >
        <ProjectFilters
          search={search}
          onSearchChange={setSearch}
          statusFilter={statusFilter}
          onStatusFilterChange={setStatusFilter}
          riskFilter={riskFilter}
          onRiskFilterChange={setRiskFilter}
        />
      </motion.div>

      {/* Projects Grid */}
      {filteredProjects.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {filteredProjects.map((project, idx) => (
            <ProjectCard
              key={project.id}
              project={project}
              index={idx}
              onEdit={handleEdit}
              onToggleStatus={handleToggleStatus}
              onDelete={(p) => setDeleteProject(p)}
            />
          ))}
        </div>
      ) : (
        <EmptyState
          icon={FolderKanban}
          title="No projects found"
          description={
            search || statusFilter !== "all" || riskFilter !== "all"
              ? "Try adjusting your search terms or filters."
              : "Create your first security project to organize targets and scans."
          }
          action={
            !search && statusFilter === "all" && riskFilter === "all" ? (
              <Button onClick={handleCreateNew} className="gap-2">
                <Plus className="h-4 w-4" />
                Create Project
              </Button>
            ) : undefined
          }
        />
      )}

      {/* Create / Edit Modal */}
      <ProjectModal
        open={modalOpen}
        projectToEdit={editingProject}
        onClose={() => setModalOpen(false)}
        onSave={handleSaveProject}
      />

      {/* Delete Confirmation Dialog */}
      <DeleteProjectDialog
        project={deleteProject}
        open={Boolean(deleteProject)}
        onClose={() => setDeleteProject(null)}
        onConfirm={handleDeleteConfirm}
      />
    </div>
  )
}
