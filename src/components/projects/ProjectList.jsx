import React, { useEffect, useState } from 'react';
import ProjectCard from './ProjectCard';
import { Briefcase, Plus } from 'lucide-react';

const STORAGE_KEY = 'ns_projects';

const DEFAULT_PROJECTS = [
    {
        id: 'proj-a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        name: 'Production Gateway',
        description: 'Main inference endpoint with full defense pipeline. Handles all customer-facing LLM traffic with DLP and threat classification.',
        api_keys: [
            { id: 'k1', name: 'prod-primary', key: 'sk-prod-a9c8f2b1d3e4f5a6b7c8d9e0f1a2b3c4' },
            { id: 'k2', name: 'prod-readonly', key: 'sk-ro-1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d' },
        ],
    },
    {
        id: 'proj-f7e6d5c4-b3a2-1098-fedc-ba0987654321',
        name: 'Staging / QA',
        description: 'Pre-production environment for testing new security rules and model updates before deployment.',
        api_keys: [
            { id: 'k3', name: 'staging-dev', key: 'sk-stg-x7y8z9a0b1c2d3e4f5g6h7i8j9k0l1m' },
        ],
    },
    {
        id: 'proj-12345678-abcd-ef01-2345-6789abcdef01',
        name: 'Red Team Sandbox',
        description: 'Isolated environment for adversarial testing. No rate limits, full logging, defense system optional.',
        api_keys: [
            { id: 'k4', name: 'redteam-unrestricted', key: 'sk-rt-m2n3o4p5q6r7s8t9u0v1w2x3y4z5a6b' },
            { id: 'k5', name: 'redteam-observer', key: 'sk-obs-c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2' },
        ],
    },
];

const ProjectList = () => {
    const [projects, setProjects] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // Try backend first
        fetch('http://localhost:8000/api/projects/')
            .then(res => res.json())
            .then(data => {
                if (Array.isArray(data) && data.length > 0) {
                    setProjects(data);
                } else {
                    loadLocal();
                }
                setLoading(false);
            })
            .catch(() => {
                loadLocal();
                setLoading(false);
            });
    }, []);

    const loadLocal = () => {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
            try { setProjects(JSON.parse(stored)); } catch { setProjects(DEFAULT_PROJECTS); }
        } else {
            setProjects(DEFAULT_PROJECTS);
            localStorage.setItem(STORAGE_KEY, JSON.stringify(DEFAULT_PROJECTS));
        }
    };

    const addProject = () => {
        const newProj = {
            id: 'proj-' + crypto.randomUUID(),
            name: `New Project ${projects.length + 1}`,
            description: 'Describe this project workspace and its purpose.',
            api_keys: [{ id: 'k-' + Date.now(), name: 'default-key', key: 'sk-' + crypto.randomUUID().replace(/-/g, '').slice(0, 32) }],
        };
        const updated = [...projects, newProj];
        setProjects(updated);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    };

    return (
        <div className="flex flex-col h-full bg-gray-900 text-white p-6 gap-6 overflow-y-auto w-full">
            <div className="flex justify-between items-end">
                <div>
                    <h1 className="text-2xl font-bold font-mono text-cyan-400 mb-2 flex items-center gap-3">
                        <Briefcase className="w-6 h-6" /> PROJECT WORKSPACES
                    </h1>
                    <p className="text-sm text-gray-400">Manage separate environments, isolation boundaries, and API credentials.</p>
                </div>
                <button
                    onClick={addProject}
                    className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 rounded-lg text-sm font-semibold transition-colors"
                >
                    <Plus className="w-4 h-4" /> New Project
                </button>
            </div>

            {loading ? (
                <div className="text-gray-500 flex-1 flex items-center justify-center">Loading organizational structure...</div>
            ) : projects.length === 0 ? (
                <div className="text-gray-500 flex-1 flex items-center justify-center">No projects configured. Create one to begin.</div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {projects.map((proj) => (
                        <ProjectCard key={proj.id} project={proj} />
                    ))}
                </div>
            )}
        </div>
    );
};

export default ProjectList;
