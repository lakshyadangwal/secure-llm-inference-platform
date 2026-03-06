import React, { useState, useRef } from 'react';
import { api } from '../services/api';

const RagScanner = () => {
    const [file, setFile] = useState(null);
    const [isScanning, setIsScanning] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState(null);
    const fileInputRef = useRef(null);

    const handleFileChange = (e) => {
        const selectedFile = e.target.files[0];
        if (selectedFile) {
            setFile(selectedFile);
            setResults(null);
            setError(null);
        }
    };

    const handleDragOver = (e) => {
        e.preventDefault();
        e.stopPropagation();
    };

    const handleDrop = (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            setFile(e.dataTransfer.files[0]);
            setResults(null);
            setError(null);
        }
    };

    const startScan = async () => {
        if (!file) return;

        setIsScanning(true);
        setError(null);
        setResults(null);

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch(`${api.baseURL}/api/rag/scan`, {
                method: 'POST',
                body: formData,
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            if (data.status === 'error') {
                setError(data.message);
            } else {
                setResults(data);
            }
        } catch (e) {
            setError(`Failed to scan document: ${e.message}`);
        } finally {
            setIsScanning(false);
        }
    };
};

export default RagScanner;
