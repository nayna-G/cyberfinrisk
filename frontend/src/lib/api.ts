import { ScanResults, CompanyContext, VulnInput, Project, ProjectDetail } from "./types";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function fetchAPI<T>(endpoint: string, options?: RequestInit): Promise<T> {
    const url = `${API_URL}${endpoint}`;
    console.log(`[API] Fetching: ${url}`);
    const response = await fetch(url, {
        ...options,
        headers: {
            "Content-Type": "application/json",
            ...options?.headers,
        },
    });

    if (!response.ok) {
        let errorData;
        try {
            errorData = await response.json();
        } catch (e) {
            errorData = { detail: response.statusText };
        }
        throw new Error(errorData.detail || "An unexpected error occurred");
    }

    return response.json();
}

export const api = {
    async health(): Promise<{ status: string; version: string }> {
        return fetchAPI("/health");
    },

    async analyzeManual(payload: {
        vulnerabilities: VulnInput[];
        company: CompanyContext;
        gemini_api_key: string | null;
    }): Promise<ScanResults> {
        return fetchAPI("/analyze-manual", {
            method: "POST",
            body: JSON.stringify(payload),
        });
    },

    async scanRepo(payload: {
        company: CompanyContext;
        repo_url: string;
        branch: string;
        gemini_api_key: string | null;
    }): Promise<ScanResults> {
        return fetchAPI("/scan-repo", {
            method: "POST",
            body: JSON.stringify(payload),
        });
    },

    async remediate(payload: {
        file_path: string;
        line: number;
        code_context: string;
        bug_type: string;
        gemini_api_key?: string | null;
    }): Promise<{ success: boolean; valid_syntax: boolean; explanation: string }> {
        return fetchAPI("/remediate", {
            method: "POST",
            body: JSON.stringify(payload),
        });
    },

    async createOrganization(payload: {
        name: string;
        slug: string;
        plan: string;
        creator_uuid: string;
    }): Promise<any> {
        return fetchAPI("/api/orgs", {
            method: "POST",
            body: JSON.stringify(payload),
        });
    },

    async listOrganizations(user_uuid?: string): Promise<any[]> {
        const endpoint = user_uuid ? `/api/orgs?user_uuid=${user_uuid}` : "/api/orgs";
        return fetchAPI(endpoint);
    },

    async updateOrganization(org_id: string, payload: { name?: string; plan?: string }): Promise<any> {
        return fetchAPI(`/api/orgs/${org_id}`, {
            method: "PATCH",
            body: JSON.stringify(payload),
        });
    },

    async deleteOrganization(org_id: string): Promise<void> {
        await fetchAPI(`/api/orgs/${org_id}`, { method: "DELETE" });
    },

    async listGroups(org_id: string): Promise<any[]> {
        return fetchAPI(`/api/orgs/${org_id}/groups`);
    },

    async createGroup(org_id: string, payload: {
        name: string;
        description?: string;
        creator_uuid: string;
    }): Promise<any> {
        return fetchAPI(`/api/orgs/${org_id}/groups`, {
            method: "POST",
            body: JSON.stringify({ ...payload, org_id }),
        });
    },

    async updateGroup(group_id: string, payload: {
        name?: string;
        description?: string;
        auto_scan?: boolean;
        enforce_policies?: boolean;
    }): Promise<any> {
        return fetchAPI(`/api/groups/${group_id}`, {
            method: "PATCH",
            body: JSON.stringify(payload),
        });
    },

    async deleteGroup(group_id: string): Promise<void> {
        await fetchAPI(`/api/groups/${group_id}`, { method: "DELETE" });
    },

    // ── Members & Invites ────────────────────────────────────────────────────

    async listMembers(org_id: string): Promise<any[]> {
        return fetchAPI(`/api/orgs/${org_id}/members`);
    },

    async inviteMember(org_id: string, payload: { invited_email: string; role: string; inviter_uuid: string }): Promise<any> {
        return fetchAPI(`/api/orgs/${org_id}/invite`, {
            method: "POST",
            body: JSON.stringify(payload),
        });
    },

    async getInvite(token: string): Promise<any> {
        return fetchAPI(`/api/invites/${token}`);
    },

    async acceptInvite(token: string, user_uuid: string): Promise<any> {
        return fetchAPI(`/api/invites/${token}/accept?user_uuid=${user_uuid}`, {
            method: "POST",
        });
    },

    // ── Notifications ────────────────────────────────────────────────────────

    async getNotifications(user_uuid: string): Promise<any[]> {
        return fetchAPI(`/api/notifications/${user_uuid}`);
    },

    async markNotificationRead(id: string): Promise<any> {
        return fetchAPI(`/api/notifications/${id}/read`, { method: "PATCH" });
    },

    async deleteNotification(id: string): Promise<void> {
        await fetchAPI(`/api/notifications/${id}`, { method: "DELETE" });
    },

    // ── Projects ──────────────────────────────────────────────────────────────

    async createProject(payload: {
        repo_url: string;
        branch: string;
        company: CompanyContext;
        org_id: string;
        group_id: string;
        created_by: string;
        gemini_api_key: string | null;
    }): Promise<ProjectDetail> {
        return fetchAPI("/api/projects", {
            method: "POST",
            body: JSON.stringify(payload),
        });
    },

    async listProjects(org_id: string, group_id?: string, user_uuid?: string): Promise<Project[]> {
        let endpoint = `/api/projects?org_id=${org_id}`;
        if (group_id) endpoint += `&group_id=${group_id}`;
        if (user_uuid) endpoint += `&user_uuid=${user_uuid}`;
        return fetchAPI(endpoint);
    },

    async getProject(project_id: string): Promise<ProjectDetail> {
        return fetchAPI(`/api/projects/${project_id}`);
    },

    async deleteProject(project_id: string): Promise<void> {
        await fetchAPI(`/api/projects/${project_id}`, { method: "DELETE" });
    },

    async scanAllProjects(org_id: string, group_id?: string, user_uuid?: string): Promise<any> {
        let endpoint = `/api/projects/scan-all?org_id=${org_id}`;
        if (group_id) endpoint += `&group_id=${group_id}`;
        if (user_uuid) endpoint += `&user_uuid=${user_uuid}`;
        return fetchAPI(endpoint, { method: "POST" });
    },
};
