import React, { useEffect, useState } from 'react';
import ProjectCard from './ProjectCard';
import { Briefcase, Plus } from 'lucide-react';

const ProjectList = () => {
    const [projects, setProjects] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetch('http://localhost:8000/api/projects/')
            .then(res => res.json())
            .then(data => {
                setProjects(data);
                setLoading(false);
            })
            .catch(err => {
                console.error(err);
                setLoading(false);
            });
    }, []);

    return (
        <div className="flex flex-col h-full bg-gray-900 text-white p-6 gap-6 overflow-y-auto w-full">
            <div className="flex justify-between items-end">
                <div>
                    <h1 className="text-2xl font-bold font-mono text-cyan-400 mb-2 flex items-center gap-3">
                        <Briefcase className="w-6 h-6" /> PROJECT WORKSPACES
                    </h1>
                    <p className="text-sm text-gray-400">Manage separate environments, isolation boundaries, and API credentials.</p>
                </div>
                <button className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 rounded-lg text-sm font-semibold transition-colors">
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
