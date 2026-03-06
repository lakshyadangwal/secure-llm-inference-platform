import React, { useState, useRef } from 'react';
import { api } from '../services/api';

const RagScanner = () => {
    const [file, setFile] = useState(null);
    const [isScanning, setIsScanning] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState(null);
    const fileInputRef = useRef(null);
};

export default RagScanner;
